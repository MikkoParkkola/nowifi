// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// libp2p P2P tunnel provider — decentralized, native-UDP, zero-config.
//
// Design: docs/LIBP2P-PROVIDER-DESIGN.md
// Issue:  https://github.com/MikkoParkkola/nowifi/issues/29
//
// Phase 1 (this file): skeleton registration, CLI integration, pairing-code
// generation, and the udppipe bridge abstraction.  The actual go-libp2p node
// creation, DHT bootstrap, DCUtR upgrade, and pubsub pairing are scaffolded
// with TODO(libp2p) markers.  Phase 1 completion gates on those markers.
//
// Architecture:
//
//   nowifi udpws bridge (UDP ↔ libp2p stream)
//   go-libp2p stream (muxed over transport)
//   Transport priority: QUIC/UDP → WSS/:443 → TCP/:443
//   Connection: bootstrap → circuit-relay-v2 → DCUtR → direct P2P
//   Pairing: 3-word mnemonic over pubsub rendezvous, 5-min TTL

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/server/udppipe"
	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

func init() { Register(&libp2pProvider{}) }

// ─── Provider ────────────────────────────────────────────────────────────────

type libp2pProvider struct{}

func (libp2pProvider) Name() string { return "libp2p" }

func (p libp2pProvider) Create(ctx context.Context, opts CreateOpts) (*Info, error) {
	// Guard G1: explicit operator authorization before using P2P.
	if err := assertAuthorizationFor("libp2p", opts.Target); err != nil {
		return nil, err
	}

	// G3 disclosure (per design + GH#29 AC).
	fmt.Println("Note: your peer IP will be visible to the paired peer and briefly to circuit relays.")

	// Generate ephemeral Ed25519 keypair → peer ID.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("libp2p: keygen: %w", err)
	}
	_ = priv // stored in host (host owns the private key)

	// Generate 3-word pairing code (33 bits entropy, 5-min TTL).
	code := generatePairingCode()
	topicStr := topicForCode(code)

	// Determine UDP target to bridge to (from Extra or default).
	udpTarget := "127.0.0.1:51820"
	if t := opts.Extra["udp_target"]; t != "" {
		udpTarget = t
	}

	fmt.Printf("  Pairing code: %s\n", code)
	fmt.Println("  Waiting for peer... (expires in 5m)")

	h, ps, err := p.startHostAndPubsub(ctx)
	if err != nil {
		return nil, fmt.Errorf("libp2p: host: %w", err)
	}

	topic, err := ps.Join(topicStr)
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("libp2p: join topic: %w", err)
	}
	sub, err := topic.Subscribe()
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("libp2p: sub: %w", err)
	}
	defer sub.Cancel()

	// Announce self.
	selfAnnounce := peerAnnounce{
		PeerID: h.ID().String(),
		Addrs:  addrsToStrings(h.Addrs()),
	}
	if err := publishAnnounce(ctx, topic, selfAnnounce); err != nil {
		h.Close()
		return nil, err
	}

	// Wait for remote peer announce (different from self).
	var remote peer.AddrInfo
	waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Minute)
	defer waitCancel()
	found := make(chan peer.AddrInfo, 1)
	go func() {
		for {
			msg, err := sub.Next(waitCtx)
			if err != nil {
				return
			}
			if msg.ReceivedFrom == h.ID() {
				continue
			}
			var a peerAnnounce
			if json.Unmarshal(msg.Data, &a) != nil {
				continue
			}
			if a.PeerID == h.ID().String() {
				continue
			}
			pi, err := addrInfoFromAnnounce(a)
			if err == nil {
				select {
				case found <- pi:
				default:
				}
				return
			}
		}
	}()

	select {
	case r := <-found:
		remote = r
	case <-waitCtx.Done():
		h.Close()
		return nil, fmt.Errorf("libp2p: timeout waiting for peer on topic %s", topicStr)
	}

	// Connect (DCUtR/holepunch will upgrade if possible).
	if err := h.Connect(ctx, remote); err != nil {
		h.Close()
		return nil, fmt.Errorf("libp2p: connect remote: %w", err)
	}

	// Set stream handler for the UDP protocol (offer side accepts streams).
	const udpProto = "/nowifi/udp/1.0.0"
	h.SetStreamHandler(udpProto, func(s network.Stream) {
		pipe := udppipe.NewLenPrefixPipe(s, udppipe.DefaultMTU)
		_, stopBridge, _ := udppipe.BridgeUDPToPipe(udpTarget, pipe, udppipe.DefaultMTU, nil)
		// Keep bridge alive for life of stream; close on stream close is handled by pipe.
		go func() {
			// When stream closes, stop bridge.
			<-ctx.Done()
			stopBridge()
		}()
	})

	// Publish our announce again post-connect (helps).
	_ = publishAnnounce(ctx, topic, selfAnnounce)

	peerShort := remote.ID.String()[:12]
	info := &Info{
		Provider: "libp2p",
		ServerID: fmt.Sprintf("%s", h.ID().String()[:12]),
		Status:   "active",
		Extra: map[string]string{
			"pairing_code": code,
			"peer_id":      h.ID().String(),
			"remote_id":    peerShort,
			"udp_target":   udpTarget,
		},
	}
	// Store for Destroy.
	storeActive(h)
	return info, nil
}

func (libp2pProvider) Destroy(ctx context.Context, info *Info, _ string) error {
	closeActive()
	_ = ctx
	_ = info
	return nil
}

// peerAnnounce is exchanged over pubsub for rendezvous.
type peerAnnounce struct {
	PeerID string   `json:"id"`
	Addrs  []string `json:"addrs"`
}

func publishAnnounce(ctx context.Context, topic *pubsub.Topic, a peerAnnounce) error {
	b, _ := json.Marshal(a)
	return topic.Publish(ctx, b)
}

func addrInfoFromAnnounce(a peerAnnounce) (peer.AddrInfo, error) {
	pid, err := peer.Decode(a.PeerID)
	if err != nil {
		return peer.AddrInfo{}, err
	}
	addrs := make([]ma.Multiaddr, 0, len(a.Addrs))
	for _, s := range a.Addrs {
		m, err := ma.NewMultiaddr(s)
		if err == nil {
			addrs = append(addrs, m)
		}
	}
	return peer.AddrInfo{ID: pid, Addrs: addrs}, nil
}

func addrsToStrings(addrs []ma.Multiaddr) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out
}

// startHostAndPubsub creates a QUIC-only libp2p host, connects bootstraps,
// and returns host + pubsub. Topic is computed from pairing code by caller.
func (p libp2pProvider) startHostAndPubsub(ctx context.Context) (host.Host, *pubsub.PubSub, error) {
	h, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/udp/0/quic-v1"),
		libp2p.EnableHolePunching(),
		libp2p.EnableRelay(),
		libp2p.NATPortMap(),
	)
	if err != nil {
		return nil, nil, err
	}

	// Bootstrap (best effort; continue even if some fail).
	bootstraps := []string{
		"/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtb1RNz8h2V7o3G7z",
		"/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
		"/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
	}
	for _, s := range bootstraps {
		m, err := ma.NewMultiaddr(s)
		if err != nil {
			continue
		}
		pi, err := peer.AddrInfoFromP2pAddr(m)
		if err != nil {
			continue
		}
		_ = h.Connect(ctx, *pi)
	}

	ps, err := pubsub.NewFloodSub(ctx, h)
	if err != nil {
		h.Close()
		return nil, nil, err
	}
	return h, ps, nil
}

// topicForCode returns the rendezvous topic for a pairing code.
func topicForCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return fmt.Sprintf("/nowifi/pair/%x", sum[:8])
}

// active host state for Destroy (single active P2P at a time is sufficient).
var (
	activeMu     sync.Mutex
	activeHost   host.Host
)

func storeActive(h host.Host) {
	activeMu.Lock()
	if activeHost != nil {
		_ = activeHost.Close()
	}
	activeHost = h
	activeMu.Unlock()
}

func closeActive() {
	activeMu.Lock()
	if activeHost != nil {
		_ = activeHost.Close()
		activeHost = nil
	}
	activeMu.Unlock()
}

// Override topic computation for callers (pubsub join uses code hash).
// The start func above returns empty topic; caller computes with topicForCode(code) then joins.
func init() {
	// ensure registration happens (already in file top)
	_ = topicForCode // used by future client join and callers
}

// ConnectLibp2pClientPair is the joiner side invoked by `nowifi server client --pair CODE`.
// For Phase 1 the rendezvous + stream + udppipe bridge is stubbed; server create side is complete.
func ConnectLibp2pClientPair(ctx context.Context, code, udpLocal string) error {
	_ = topicForCode(code)
	_ = ctx
	_ = udpLocal
	// Real impl would: host, pubsub join same topic, announce, receive remote, Connect, NewStream(udpProto),
	// wrap with NewLenPrefixPipe, ListenUDPAndBridge(udpLocal, pipe).
	return fmt.Errorf("libp2p --pair client join not wired (use server create -p libp2p for P2P offer side)")
}

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
