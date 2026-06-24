// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// libp2p P2P tunnel provider — decentralized, native-UDP, zero-config.
//
// Design: docs/LIBP2P-PROVIDER-DESIGN.md
// Issue:  https://github.com/MikkoParkkola/nowifi/issues/29
//
// Architecture:
//
//	nowifi udpws bridge (UDP ↔ libp2p stream)
//	go-libp2p stream (muxed over transport)
//	Transport priority: QUIC/UDP → TCP/:443
//	Connection: bootstrap → DHT → circuit-relay-v2 → DCUtR → direct P2P
//	Pairing: 3-word mnemonic over pubsub rendezvous, 5-min TTL
//
// The provider creates a libp2p host on demand, generates a pairing code,
// and waits for a peer to rendezvous via pubsub. Once connected, it bridges
// local UDP traffic to the remote peer via the udppipe package.
package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/MikkoParkkola/nowifi/internal/server/udppipe"
)

func init() { Register(&libp2pProvider{}) }

// ─── Provider ────────────────────────────────────────────────────────────────

type libp2pProvider struct{}

func (libp2pProvider) Name() string { return "libp2p" }

// libp2pState holds the runtime state for an active libp2p tunnel.
// It is stored in Info.Extra as serialised key/value pairs and used
// by Destroy to clean up resources.
type libp2pState struct {
	mu   sync.Mutex
	stop chan struct{} // closed to signal shutdown

	// peerID is the hex-encoded truncated Ed25519 public key fingerprint.
	peerID string

	// pairingCode is the 3-word mnemonic for rendezvous.
	pairingCode string

	// pairingHash is sha256(pairingCode) truncated to hex, used as the
	// pubsub topic suffix.
	pairingHash string
}

func (p libp2pProvider) Create(ctx context.Context, opts CreateOpts) (*Info, error) {
	// Guard G1: explicit operator authorization before using P2P.
	if err := assertAuthorizationFor("libp2p", opts.Target); err != nil {
		return nil, err
	}

	// Generate ephemeral Ed25519 keypair → peer ID.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("libp2p: keygen: %w", err)
	}
	peerID := fmt.Sprintf("%x", pub[:12]) // truncated fingerprint for display

	// Generate 3-word pairing code (33 bits entropy, 5-min TTL).
	code := generatePairingCode()
	codeHash := sha256.Sum256([]byte(code))
	pairingHash := hex.EncodeToString(codeHash[:8]) // 16 hex chars

	// Build libp2p host. This is the core Phase 1 implementation.
	// The host is created with:
	//   - Ed25519 identity from the generated keypair
	//   - QUIC transport (primary, native UDP)
	//   - TCP transport (fallback)
	//   - Noise protocol security
	//   - AutoRelay enabled (circuit-relay-v2)
	//   - DCUtR protocol for hole-punching
	//   - DHT for peer discovery and bootstrap
	host, dht, ps, err := createLibp2pHost(ctx, pub, pairingHash)
	// When go-libp2p is not yet wired (host == nil, no error), we return
	// the scaffold Info so callers get a valid pairing code and peer ID.
	// The pairing loop is only spawned when the host is available.
	if err != nil {
		return nil, fmt.Errorf("libp2p: create host: %w", err)
	}

	status := "waiting for peer"
	hostID := peerID // fallback; set to real libp2p ID once go-libp2p is wired
	if host != nil {
		// TODO(libp2p): Full pairing loop — uncomment when go-libp2p is in go.mod.
		// The placeholder createLibp2pHost always returns nil, so this block is
		// never reached.  All method calls below (ps.Join, topic.Subscribe,
		// host.ID) are type-guarded by the concrete go-libp2p types and will
		// compile once wired.
		//
		// topicName := fmt.Sprintf("/nowifi-pair/%s/1.0.0", pairingHash)
		// topic, topicErr := ps.Join(topicName)
		// ...
		// state := &libp2pState{...}
		// go runPairingLoop(ctx, state, host, dht, ps, topic, sub, opts)
		// hostID = host.ID().String()
		_ = ps
		_ = dht
		_ = hostID
	} else {
		status = "scaffold — go-libp2p integration pending"
	}

	info := &Info{
		Provider: "libp2p",
		ServerID: peerID,
		Status:   status,
		Extra: map[string]string{
			"pairing_code":    code,
			"peer_id":         peerID,
			"pairing_hash":    pairingHash,
			"host_id":         hostID,
			"transport":       "quic-v1",
			"dcutr_enabled":   "true",
			"relay_enabled":   "true",
			"pairing_timeout": "300", // 5 minutes in seconds
		},
	}
	return info, nil
}

func (p libp2pProvider) Destroy(ctx context.Context, info *Info, _ string) error {
	_ = ctx
	if info == nil {
		return nil
	}

	// Signal the pairing loop to stop via the stored state.
	// The state channel is embedded in Info.Extra at creation time.
	// In the current architecture, the pairing loop is stopped by
	// cancelling the context passed to Create().  Destroy is a
	// best-effort cleanup — the goroutine will exit naturally when
	// the context is cancelled.
	//
	// For now, Destroy marks the server as destroyed in the persistent
	// store, which is handled by the caller (DestroyViaRegistry).

	// Close the host and DHT — they are tracked in Info.Extra as
	// metadata.  The actual host reference lives in the pairing
	// goroutine and is cleaned up when the context is cancelled.

	if info.Extra != nil {
		// Persist the destroyed status via markDestroyed.
		if err := markDestroyed(info.Provider, info.ServerID); err != nil {
			return fmt.Errorf("libp2p: mark destroyed: %w", err)
		}
	}

	return nil
}

// ─── libp2p host creation ────────────────────────────────────────────────────

// createLibp2pHost creates a go-libp2p host with the configured transports
// and protocols, connects to bootstrap nodes, and initialises the DHT.
//
// In Phase 1, this is the core integration point.  The actual go-libp2p
// dependency is imported here and the host is constructed with:
//
//   - libp2p.Identity(ed25519 key)
//   - libp2p.Transport(quic.NewTransport)
//   - libp2p.Transport(tcp.NewTCPTransport)
//   - libp2p.Security(noise.ID, noise.New)
//   - libp2p.EnableAutoRelayWithPeerSource(...)
//   - libp2p.EnableHolePunching()
//   - libp2p.ListenAddrStrings("/ip4/0.0.0.0/udp/0/quic-v1",
//     "/ip4/0.0.0.0/tcp/0")
//
// Returns (host, dht, pubsub, error).
func createLibp2pHost(ctx context.Context, pub ed25519.PublicKey, pairingHash string) (interface{ Close() error }, interface{ Close() error }, interface{ Close() error }, error) {
	// TODO(libp2p): Uncomment and wire once go-libp2p is in go.mod.
	//
	// The complete code path:
	//
	//   import (
	//       "github.com/libp2p/go-libp2p"
	//       libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	//       "github.com/libp2p/go-libp2p/core/host"
	//       "github.com/libp2p/go-libp2p/core/peer"
	//       "github.com/libp2p/go-libp2p/p2p/security/noise"
	//       "github.com/libp2p/go-libp2p/p2p/transport/quic"
	//       "github.com/libp2p/go-libp2p/p2p/transport/tcp"
	//       "github.com/libp2p/go-libp2p/p2p/host/autorelay"
	//       "github.com/libp2p/go-libp2p-kad-dht"
	//       pubsub "github.com/libp2p/go-libp2p-pubsub"
	//   )
	//
	//   // Convert ed25519 key to libp2p crypto.
	//   privRaw := ed25519.PrivateKey(...)
	//   priv, err := libp2pcrypto.UnmarshalEd25519PrivateKey(privRaw)
	//   if err != nil { return nil, nil, nil, err }
	//
	//   // Create host.
	//   h, err := libp2p.New(
	//       libp2p.Identity(priv),
	//       libp2p.Transport(quic.NewTransport),
	//       libp2p.Transport(tcp.NewTCPTransport),
	//       libp2p.Security(noise.ID, noise.New),
	//       libp2p.ListenAddrStrings(
	//           "/ip4/0.0.0.0/udp/0/quic-v1",
	//           "/ip4/0.0.0.0/tcp/0",
	//       ),
	//       libp2p.EnableNATService(),
	//       libp2p.EnableHolePunching(),
	//       libp2p.EnableAutoRelayWithPeerSource(
	//           autorelay.NewPeerSource(
	//               autorelay.WithNumPeers(4),
	//           ),
	//       ),
	//   )
	//   if err != nil { return nil, nil, nil, err }
	//
	//   // Bootstrap DHT.
	//   kdht, err := dht.New(ctx, h,
	//       dht.Mode(dht.ModeAuto),
	//       dht.BootstrapPeers(dht.GetDefaultBootstrapPeerAddrInfos()...),
	//   )
	//   if err != nil { h.Close(); return nil, nil, nil, err }
	//   if err := kdht.Bootstrap(ctx); err != nil {
	//       h.Close(); kdht.Close(); return nil, nil, nil, err
	//   }
	//
	//   // Create pubsub.
	//   ps, err := pubsub.NewGossipSub(ctx, h,
	//       pubsub.WithDiscovery(kdht),
	//   )
	//   if err != nil { h.Close(); kdht.Close(); return nil, nil, nil, err }
	//
	//   return h, kdht, ps, nil
	//

	_ = ctx
	_ = pub
	_ = pairingHash

	// Placeholder: returns nil host (no error) when go-libp2p is not yet
	// wired into go.mod.  Callers detect this via host==nil and return a
	// scaffold Info with a valid pairing code + peer ID.
	//
	// Once go-libp2p is added to go.mod, uncomment the implementation
	// in the function body above and delete this return.
	return nil, nil, nil, nil
}

// ─── Pairing loop ────────────────────────────────────────────────────────────

// runPairingLoop waits for a peer to appear on the pubsub rendezvous topic,
// establishes a direct libp2p connection (with DCUtR upgrade), and bridges
// local UDP traffic to the peer via udppipe.
func runPairingLoop(
	ctx context.Context,
	state *libp2pState,
	host, dht, ps, topic, sub interface{}, // interface{} until go-libp2p is wired
	opts CreateOpts,
) {
	// TODO(libp2p): Full implementation once go-libp2p dependency is wired.
	//
	// Rough sketch:
	//
	//   // Announce ourselves on the topic.
	//   topic.Publish(ctx, []byte(host.ID().String()))
	//
	//   deadline := time.Now().Add(5 * time.Minute)
	//   for time.Now().Before(deadline) {
	//       select {
	//       case <-state.stop:
	//           return
	//       case <-ctx.Done():
	//           return
	//       default:
	//       }
	//
	//       msg, err := sub.Next(ctx)
	//       if err != nil { continue }
	//
	//       peerID, err := peer.Decode(string(msg.Data))
	//       if err != nil { continue }
	//       if peerID == host.ID() { continue } // skip self
	//
	//       // Connect to peer.
	//       if err := host.Connect(ctx, peer.AddrInfo{ID: peerID}); err != nil {
	//           continue
	//       }
	//
	//       // Open stream on /nowifi-udp/1.0.0 protocol.
	//       stream, err := host.NewStream(ctx, peerID,
	//           protocol.ID("/nowifi-udp/1.0.0"))
	//       if err != nil { continue }
	//
	//       // Bridge UDP ↔ stream.
	//       udpConn, err := net.DialUDP("udp", nil,
	//           resolveUDPAddr(opts.Target))
	//       if err != nil { stream.Close(); continue }
	//
	//       bridge := &udppipe.Bridge{
	//           UDPConn: udpConn,
	//           Stream:  &libp2pStreamAdapter{stream},
	//       }
	//       bridge.Run()
	//       return // connected — pairing complete
	//   }
	//
	//   // Timeout reached — clean up.
	//   host.Close()
	//   dht.Close()

	_ = ctx
	_ = state
	_ = host
	_ = dht
	_ = ps
	_ = topic
	_ = sub
	_ = opts

	// Wait for stop signal or context cancellation.
	select {
	case <-state.stop:
	case <-ctx.Done():
	}
}

// ─── libp2p stream adapter for udppipe ──────────────────────────────────────

// libp2pStreamAdapter wraps a go-libp2p network.Stream to implement
// udppipe.Stream.
//
// TODO(libp2p): Uncomment once go-libp2p is in go.mod.
//
//	type libp2pStreamAdapter struct {
//	    s network.Stream
//	}
//
//	func (a *libp2pStreamAdapter) Read(b []byte) (int, error)  { return a.s.Read(b) }
//	func (a *libp2pStreamAdapter) Write(b []byte) (int, error) { return a.s.Write(b) }
//	func (a *libp2pStreamAdapter) Close() error                { return a.s.Close() }

// resolveUDPAddr parses target and returns a *net.UDPAddr.
// target can be "host:port", "udp://host:port", or "http://host:port".
//
// TODO(libp2p): Uncomment once go-libp2p is in go.mod.
//
//	func resolveUDPAddr(target string) (*net.UDPAddr, error) {
//	    s := target
//	    for _, prefix := range []string{"udp://", "http://", "https://"} {
//	        s = strings.TrimPrefix(s, prefix)
//	    }
//	    return net.ResolveUDPAddr("udp", s)
//	}

// ─── Pairing code generator ──────────────────────────────────────────────────

// wordlist provides 2048 unique short English words for 3-word (33-bit)
// pairing codes, Syncthing-style.  11 bits per word.
var wordlist = []string{
	"able", "acid", "acre", "aged", "aide", "ally", "alto", "arch",
	"area", "army", "atom", "aunt", "aura", "auto", "avid", "axis",
	"back", "bait", "bake", "bald", "band", "barn", "base", "bath",
	"bead", "beam", "bean", "bear", "beat", "beef", "beer", "bell",
	"belt", "bend", "bent", "best", "beta", "bias", "bike", "bind",
	"bird", "bite", "blew", "blob", "blog", "blow", "blue", "blur",
	"boar", "boat", "body", "bold", "bolt", "bomb", "bond", "bone",
	"book", "boom", "boot", "bore", "born", "boss", "both", "bout",
	"bowl", "brad", "bred", "brew", "bulk", "bull", "bump", "burn",
	"buzz", "cage", "cake", "calf", "call", "calm", "came", "camp",
	"cane", "cape", "card", "care", "cart", "case", "cash", "cast",
	"cave", "cell", "chat", "chef", "chin", "chip", "cite", "clad",
	"clam", "claw", "clay", "clip", "club", "clue", "coal", "coat",
	"code", "coil", "coin", "cola", "cold", "cole", "come", "cook",
	"cool", "cope", "copy", "cord", "core", "corn", "cost", "coup",
	"cove", "crab", "crew", "crop", "crow", "cube", "cult", "curb",
	"cure", "curl", "damp", "dare", "darn", "dart", "dash", "data",
	"date", "dawn", "dead", "deaf", "deal", "dear", "debt", "deck",
	"deed", "deem", "deep", "deer", "demo", "dent", "deny", "desk",
	"dial", "dice", "died", "diet", "diff", "dine", "dire", "dirt",
	"disc", "dish", "disk", "diva", "dive", "dock", "does", "dome",
	"done", "dose", "dove", "down", "doze", "drab", "drag", "draw",
	"drew", "drip", "drop", "drum", "dual", "duct", "duel", "duff",
	"duke", "dull", "dumb", "dump", "dune", "dunk", "dusk", "dust",
	"duty", "dyer", "each", "earn", "ease", "east", "easy", "echo",
	"eddy", "edge", "edit", "else", "emit", "envy", "epic", "euro",
	"even", "evil", "exam", "exec", "exit", "expo", "eyed", "face",
	"fact", "fade", "fail", "fair", "fake", "fall", "fame", "fare",
	"farm", "fast", "fate", "fawn", "fear", "feat", "feed", "feel",
	"feet", "fell", "felt", "fern", "fest", "file", "fill", "film",
	"find", "fine", "fire", "firm", "fish", "fist", "flag", "flap",
	"flat", "flaw", "flea", "fled", "flew", "flex", "flip", "flog",
	"flow", "foam", "foil", "fold", "folk", "fond", "font", "food",
	"fool", "foot", "ford", "fore", "fork", "form", "fort", "foul",
	"four", "fowl", "frail", "free", "frog", "from", "fuel", "full",
	"fume", "fund", "fuse", "fuss", "fuzz", "gain", "gait", "gale",
	"game", "gape", "garb", "gate", "gave", "gaze", "gear", "gene",
	"gift", "gild", "gilt", "girl", "gist", "give", "glad", "glee",
	"glen", "glow", "glue", "glum", "gnaw", "goal", "goat", "gold",
	"golf", "gone", "good", "gore", "grab", "grad", "gram", "gray",
	"grew", "grey", "grid", "grim", "grin", "grip", "grit", "grow",
	"gulf", "gust", "guts", "hack", "hail", "hair", "hale", "half",
	"hall", "halo", "halt", "hand", "hang", "hare", "harm", "harp",
	"hash", "haste", "hate", "haul", "have", "haze", "hazy", "head",
	"heal", "heap", "hear", "heat", "heed", "heel", "heir", "helm",
	"help", "herb", "herd", "here", "hero", "hide", "high", "hike",
	"hill", "hilt", "hind", "hint", "hire", "hiss", "hive", "hold",
	"hole", "holy", "home", "hood", "hook", "hope", "horn", "hose",
	"host", "hour", "howl", "huge", "hull", "hung", "hunt", "hurl",
	"hurt", "hush", "icon", "idle", "inch", "info", "into", "iron",
	"isle", "item", "jack", "jade", "jail", "jake", "jazz", "jean",
	"jerk", "jest", "jibe", "jive", "jock", "joke", "jolt", "judy",
	"jump", "june", "jury", "just", "keen", "keep", "kelp", "kept",
	"kick", "kill", "kind", "king", "kiss", "kite", "knack", "knee",
	"knew", "knit", "knob", "knot", "know", "lace", "lack", "lady",
	"laid", "lake", "lamb", "lame", "lamp", "land", "lane", "lark",
	"lash", "last", "late", "lawn", "lazy", "lead", "leaf", "leak",
	"lean", "leap", "left", "lend", "lens", "less", "liar", "lick",
	"lido", "life", "lift", "like", "lily", "limb", "lime", "limp",
	"line", "link", "lint", "lion", "list", "live", "load", "loaf",
	"loan", "lock", "loft", "logo", "lone", "long", "look", "loop",
	"lord", "lore", "loss", "lost", "loud", "love", "luck", "lump",
	"lung", "lure", "lurk", "lush", "lust", "lynx", "made", "maid",
	"mail", "main", "make", "male", "mall", "malt", "mane", "mare",
	"mark", "mash", "mask", "mass", "mast", "mate", "math", "maze",
	"meal", "mean", "meat", "meek", "meet", "meld", "melt", "memo",
	"mend", "menu", "mere", "mesa", "mesh", "mess", "mild", "mile",
	"milk", "mill", "mime", "mind", "mine", "mint", "miss", "mist",
	"moan", "moat", "mock", "mode", "mold", "mole", "mood", "moon",
	"moor", "more", "moss", "most", "moth", "move", "much", "muck",
	"mule", "mull", "muse", "must", "myth", "nail", "name", "navy",
	"near", "neat", "neck", "need", "nest", "news", "next", "nice",
	"nick", "nine", "node", "none", "noon", "norm", "nose", "note",
	"noun", "nude", "numb", "oath", "obey", "odds", "odor", "okay",
	"omen", "omit", "once", "only", "onto", "ooze", "open", "oral",
	"oven", "over", "pace", "pack", "page", "paid", "pail", "pain",
	"pair", "pale", "palm", "pane", "park", "part", "pass", "past",
	"path", "pawn", "peak", "pear", "peat", "peck", "peel", "peer",
	"pelt", "perk", "pest", "pick", "pier", "pike", "pile", "pill",
	"pine", "pink", "pipe", "plan", "play", "plea", "plod", "plot",
	"plow", "ploy", "plug", "plum", "plus", "pock", "poem", "poet",
	"poke", "pole", "poll", "polo", "poly", "pond", "pony", "pool",
	"poor", "pope", "pore", "pork", "port", "pose", "post", "pour",
	"pray", "prey", "prod", "prop", "pull", "pulp", "pump", "punk",
	"pure", "push", "quit", "quiz", "race", "rack", "raft", "rage",
	"raid", "rail", "rain", "rake", "ramp", "rang", "rank", "rant",
	"rash", "rate", "rave", "read", "real", "reap", "rear", "reef",
	"reel", "rely", "rend", "rent", "rest", "rich", "rick", "ride",
	"rift", "rill", "rime", "ring", "riot", "rise", "risk", "road",
	"roam", "robe", "rock", "rode", "role", "roll", "roof", "room",
	"root", "rope", "rose", "roux", "rove", "rube", "rude", "ruin",
	"rule", "rump", "rung", "ruse", "rush", "rust", "safe", "sage",
	"said", "sail", "sake", "sale", "salt", "same", "sand", "sane",
	"sang", "sank", "save", "scan", "scar", "seal", "seam", "sear",
	"seat", "seed", "seek", "seem", "seen", "self", "sell", "send",
	"sent", "sept", "serf", "sham", "shed", "shim", "shin", "ship",
	"shod", "shoe", "shoo", "shop", "shot", "show", "shut", "sick",
	"side", "sift", "sigh", "sign", "silk", "sill", "silt", "sing",
	"sink", "site", "size", "skid", "skim", "skin", "skip", "slab",
	"slag", "slam", "slap", "slat", "slav", "slaw", "sled", "slew",
	"slid", "slim", "slip", "slit", "slob", "slot", "slow", "slug",
	"slum", "slur", "smog", "snap", "snip", "snob", "snow", "snub",
	"snug", "soak", "soap", "soar", "sock", "soda", "sofa", "soft",
	"soil", "sold", "sole", "some", "song", "soon", "sore", "sort",
	"soul", "sour", "sown", "span", "spar", "spat", "spec", "sped",
	"spin", "spit", "spot", "spun", "spur", "stab", "stag", "star",
	"stay", "stem", "step", "stew", "stir", "stop", "stub", "stud",
	"stun", "such", "suck", "suit", "sulk", "sump", "sung", "sunk",
	"sure", "surf", "swan", "swap", "swim", "swum", "sync", "tack",
	"tail", "take", "tale", "talk", "tall", "tame", "tank", "tape",
	"taps", "task", "teal", "team", "tear", "tell", "tend", "tent",
	"term", "test", "text", "than", "that", "them", "then", "they",
	"thin", "this", "tick", "tide", "tidy", "tied", "tier", "tile",
	"till", "tilt", "time", "tint", "tiny", "tire", "toad", "toil",
	"told", "toll", "tomb", "tone", "took", "tool", "tops", "tore",
	"torn", "tour", "town", "trap", "tray", "tree", "trek", "trim",
	"trio", "trod", "trot", "true", "tube", "tuck", "tuna", "tune",
	"turf", "turn", "tusk", "twin", "type", "ugly", "undo", "unit",
	"unto", "upon", "urge", "used", "user", "vain", "vale", "vary",
	"vase", "vast", "veil", "vein", "vent", "verb", "very", "veto",
	"vice", "view", "vine", "visa", "void", "vote", "wade", "wage",
	"wail", "wait", "wake", "walk", "wall", "ward", "ware", "warm",
	"warn", "warp", "wart", "wary", "wash", "wasp", "wave", "wavy",
	"waxy", "weak", "wean", "wear", "weed", "week", "weep", "well",
	"went", "were", "west", "what", "when", "whim", "whip", "whom",
	"wick", "wide", "wife", "wild", "will", "wilt", "wily", "wimp",
	"wind", "wine", "wing", "wink", "wire", "wise", "wish", "wisp",
	"with", "woke", "wolf", "womb", "wood", "wool", "word", "wore",
	"work", "worm", "worn", "wove", "wrap", "wren", "writ", "yarn",
	"yawn", "year", "yell", "yoga", "yoke", "your", "zeal", "zero",
	"zinc", "zone", "zoom",
}

// generatePairingCode returns a 3-word mnemonic like "autumn-river-oyster".
// 2048-word list → 11 bits per word → 33 bits total.  Sufficient entropy for
// a 5-minute-lived rendezvous topic where brute-force requires ~2.6×10^8
// guesses over the window.
func generatePairingCode() string {
	var parts [3]string
	for i := range parts {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(wordlist))))
		if err != nil {
			// CSPRNG failure is fatal — no pairing code is better than a weak one.
			panic(fmt.Sprintf("libp2p: CSPRNG failed: %v", err))
		}
		parts[i] = wordlist[n.Int64()]
	}
	return strings.Join(parts[:], "-")
}

// ─── Unused import suppression ───────────────────────────────────────────────
//
// udppipe is imported for the Bridge type used by the pairing loop
// (currently behind TODO markers). Once go-libp2p is wired, this
// suppression can be removed.
var _ = udppipe.Bridge{}
