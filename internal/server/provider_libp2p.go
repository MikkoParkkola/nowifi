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
	"fmt"
	"math/big"
	"strings"
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

	// Generate ephemeral Ed25519 keypair → peer ID.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("libp2p: keygen: %w", err)
	}
	_ = priv // used once the libp2p host is wired
	peerID := fmt.Sprintf("%x", pub[:12]) // truncated fingerprint for display

	// Generate 3-word pairing code (33 bits entropy, 5-min TTL).
	code := generatePairingCode()

	// TODO(libp2p): bootstrap to public DHT, announce rendezvous on
	// pubsub topic nowifi-pair-<hash(code)>, wait for peer.
	//
	// Rough sketch:
	//   1. Create go-libp2p host with QUIC transport.
	//   2. Connect to bootstrap.libp2p.io nodes.
	//   3. Subscribe to /nowifi-pair/<sha256(code)> topic.
	//   4. Exchange peer IDs + multiaddrs via pubsub.
	//   5. DCUtR upgrade → direct UDP connection.
	//   6. Bridge local UDP ↔ libp2p stream via udppipe.
	//
	// See docs/LIBP2P-PROVIDER-DESIGN.md §4 for full architecture.

	info := &Info{
		Provider: "libp2p",
		ServerID: peerID,
		Status:   "scaffold — go-libp2p integration pending",
		Extra: map[string]string{
			"pairing_code": code,
			"peer_id":      peerID,
		},
	}
	return info, nil
}

func (libp2pProvider) Destroy(ctx context.Context, info *Info, _ string) error {
	// TODO(libp2p): close libp2p host, stop DHT, cancel pubsub.
	_ = ctx
	_ = info
	return nil
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
