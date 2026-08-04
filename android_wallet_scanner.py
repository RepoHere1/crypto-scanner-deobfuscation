#!/usr/bin/env python3
"""
Android Wallet Scanner — finds every crypto wallet stored on this device.

Scans ALL accessible paths for private keys, seed phrases, keystore files,
.env files, and wallet configs. Feeds findings into the crypto_scanner
pipeline for address derivation + balance checking.

Usage:
    python3 ~/android_wallet_scanner.py              # scan + feed pipeline
    python3 ~/android_wallet_scanner.py --email      # scan + email results
    python3 ~/android_wallet_scanner.py --dry-run    # scan only, write nothing
    python3 ~/android_wallet_scanner.py --paths /sdcard/Documents
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

HOME = Path(os.path.expanduser("~"))
sys.path.insert(0, str(HOME))

# ── ANSI colors (orange/black/white theme) ────────────────────────
BOLD = "\033[1m"
DIM = "\033[2m"
RST = "\033[0m"
ORANGE = "\033[38;5;208m"
GOLD = "\033[38;5;220m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
WHITE = "\033[97m"
OK = f"{GREEN}✓{RST}"
WARN = f"{GOLD}⚠{RST}"
ERR = f"{RED}✗{RST}"

# ── Scan configuration ─────────────────────────────────────────────
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_DEPTH_HOME = 6
BINARY_RATIO = 0.30  # >30% non-printable = binary
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".cache", ".npm",
             ".ollama", ".config", ".local", ".termux", ".ssh",
             ".codewhale", ".vault", ".kalshi", "targets", "tmp",
             "backups", "bin", "forensic_exports", "mcp_kalshi",
             "ocean-cli", "CloddsBot", "HacxGPT-CLI", "kalshi_tap"}

# ── Crypto patterns ─────────────────────────────────────────────────
# BIP39 wordlist (first 4 letters of each word for matching)
BIP39_WORDS = {
    "abandon", "ability", "able", "about", "above", "absent",
    "absorb", "abstract", "absurd", "abuse", "access", "accident",
    "account", "accuse", "achieve", "acid", "acoustic", "acquire",
    "across", "act", "action", "actor", "actress", "actual", "adapt",
    "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "africa", "after",
    "again", "age", "agent", "agree", "ahead", "aim", "air", "airport",
    "aisle", "alarm", "album", "alcohol", "alert", "alien", "all",
    "alley", "allow", "almost", "alone", "alpha", "already", "also",
    "alter", "always", "amateur", "amazing", "among", "amount",
    "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer",
    "antenna", "antique", "anxiety", "any", "apart", "apology",
    "appear", "apple", "approve", "april", "arch", "arctic", "area",
    "arena", "argue", "arm", "armed", "armor", "army", "around",
    "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist",
    "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
    "asthma", "athlete", "atom", "attack", "attend", "attitude",
    "attract", "auction", "audit", "august", "aunt", "author", "auto",
    "autumn", "average", "avocado", "avoid", "awake", "aware", "away",
    "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon",
    "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana",
    "banner", "bar", "barely", "bargain", "barrel", "base", "basic",
    "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below",
    "belt", "bench", "benefit", "best", "betray", "better", "between",
    "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird",
    "birth", "bitter", "black", "blade", "blame", "blanket", "blast",
    "bleak", "bless", "blind", "blood", "blossom", "blouse", "blue",
    "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone",
    "bonus", "book", "boost", "border", "boring", "borrow", "boss",
    "bottom", "bounce", "box", "boy", "bracket", "brain", "brand",
    "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
    "bright", "bring", "brisk", "broccoli", "broken", "bronze",
    "broom", "brother", "brown", "brush", "bubble", "buddy", "budget",
    "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunker",
    "burden", "burger", "burst", "bus", "business", "busy", "butter",
    "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage",
    "cake", "call", "calm", "camera", "camp", "can", "canal",
    "cancel", "candy", "cannon", "canoe", "canvas", "canyon",
    "capable", "capital", "captain", "car", "carbon", "card", "cargo",
    "carpet", "carry", "cart", "case", "cash", "casino", "castle",
    "casual", "cat", "catalog", "catch", "category", "cattle", "caught",
    "cause", "caution", "cave", "ceiling", "celery", "cement",
    "census", "century", "cereal", "certain", "chair", "chalk",
    "champion", "change", "chaos", "chapter", "charge", "chase",
    "chat", "cheap", "check", "cheese", "chef", "cherry", "chest",
    "chicken", "chief", "child", "chimney", "choice", "choose",
    "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon",
    "circle", "citizen", "city", "civil", "claim", "clap", "clarify",
    "claw", "clay", "clean", "clerk", "clever", "click", "client",
    "cliff", "climb", "clinic", "clip", "clock", "clog", "close",
    "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch",
    "coach", "coast", "coconut", "code", "coffee", "coil", "coin",
    "collect", "color", "column", "combine", "come", "comfort",
    "comic", "common", "company", "concert", "conduct", "confirm",
    "congress", "connect", "consider", "control", "convince", "cook",
    "cool", "copper", "copy", "coral", "core", "corn", "correct",
    "cost", "cotton", "couch", "country", "couple", "course", "cousin",
    "cover", "coyote", "crack", "cradle", "craft", "cram", "crane",
    "crash", "crater", "crawl", "crazy", "cream", "credit", "creek",
    "crew", "cricket", "crime", "crisp", "critic", "crop", "cross",
    "crouch", "crowd", "crucial", "cruel", "cruise", "crumble",
    "crunch", "crush", "cry", "crystal", "cube", "culture", "cup",
    "cupboard", "curious", "current", "curtain", "curve", "cushion",
    "custom", "cute", "cycle", "dad", "damage", "damp", "dance",
    "danger", "daring", "dash", "daughter", "dawn", "day", "deal",
    "debate", "debris", "decade", "december", "decide", "decline",
    "decorate", "decrease", "deer", "defense", "define", "defy",
    "degree", "delay", "deliver", "demand", "demise", "denial",
    "dentist", "deny", "depart", "depend", "deposit", "depth",
    "deputy", "derive", "describe", "desert", "design", "desk",
    "despair", "destroy", "detail", "detect", "develop", "device",
    "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel",
    "diet", "differ", "digital", "dignity", "dilemma", "dinner",
    "dinosaur", "direct", "dirt", "disagree", "discover", "disease",
    "dish", "dismiss", "disorder", "display", "distance", "divert",
    "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll",
    "dolphin", "domain", "donate", "donkey", "donor", "door", "dose",
    "double", "dove", "draft", "dragon", "drama", "drastic", "draw",
    "dream", "dress", "drift", "drill", "drink", "drip", "drive",
    "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust",
    "dutch", "duty", "dwarf", "dynamic", "eager", "eagle", "early",
    "earn", "earth", "easily", "east", "easy", "echo", "ecology",
    "economy", "edge", "edit", "educate", "effort", "egg", "eight",
    "either", "elbow", "elder", "electric", "elegant", "element",
    "elephant", "elevator", "elite", "else", "embark", "embody",
    "embrace", "emerge", "emotion", "employ", "empower", "empty",
    "enable", "enact", "end", "endless", "endorse", "enemy", "energy",
    "enforce", "engage", "engine", "enhance", "enjoy", "enlist",
    "enough", "enrich", "enroll", "ensure", "enter", "entire",
    "entry", "envelope", "episode", "equal", "equip", "era", "erase",
    "erode", "erosion", "error", "erupt", "escape", "essay", "essence",
    "estate", "eternal", "ethics", "evidence", "evil", "evoke",
    "evolve", "exact", "example", "excess", "exchange", "excite",
    "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit",
    "exile", "exist", "exit", "exotic", "expand", "expect", "expire",
    "explain", "expose", "express", "extend", "extra", "eye", "eyebrow",
    "fabric", "face", "faculty", "fade", "faint", "faith", "fall",
    "false", "fame", "family", "famous", "fan", "fancy", "fantasy",
    "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault",
    "favorite", "feature", "february", "federal", "fee", "feed",
    "feel", "female", "fence", "festival", "fetch", "fever", "few",
    "fiber", "fiction", "field", "figure", "file", "film", "filter",
    "final", "find", "fine", "finger", "finish", "fire", "firm",
    "first", "fiscal", "fish", "fit", "fitness", "fix", "flag",
    "flame", "flash", "flat", "flavor", "flee", "flight", "flip",
    "float", "flock", "floor", "flower", "fluid", "flush", "fly",
    "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot",
    "force", "forest", "forget", "fork", "fortune", "forum", "forward",
    "fossil", "foster", "found", "fox", "fragile", "frame", "frequent",
    "fresh", "friend", "fringe", "frog", "front", "frost", "frown",
    "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury",
    "future", "gadget", "gain", "galaxy", "gallery", "game", "gap",
    "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp",
    "gate", "gather", "gauge", "gaze", "general", "genius", "genre",
    "gentle", "genuine", "gesture", "ghost", "giant", "gift",
    "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance",
    "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory",
    "glove", "glow", "glue", "goat", "goddess", "gold", "good",
    "goose", "gorilla", "gospel", "gossip", "govern", "gown", "grab",
    "grace", "grain", "grant", "grape", "grass", "gravity", "great",
    "green", "grid", "grief", "grit", "grocery", "group", "grow",
    "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun",
    "gym", "habit", "hair", "half", "hammer", "hamster", "hand",
    "happy", "harbor", "hard", "harsh", "harvest", "hat", "have",
    "hawk", "hazard", "head", "health", "heart", "heavy", "hedgehog",
    "height", "hello", "helmet", "help", "hen", "hero", "hidden",
    "high", "hill", "hint", "hip", "hire", "history", "hobby",
    "hockey", "hold", "hole", "holiday", "hollow", "home", "honey",
    "hood", "hope", "horn", "horror", "horse", "hospital", "host",
    "hotel", "hour", "hover", "hub", "huge", "human", "humble",
    "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt",
    "husband", "hybrid", "ice", "icon", "idea", "identify", "idle",
    "ignore", "ill", "illegal", "illness", "image", "imitate",
    "immense", "immune", "impact", "impose", "improve", "impulse",
    "inch", "include", "income", "increase", "index", "indicate",
    "indoor", "industry", "infant", "inflict", "inform", "inhale",
    "inherit", "initial", "inject", "injury", "inmate", "inner",
    "innocent", "input", "inquiry", "insane", "insect", "inside",
    "inspire", "install", "intact", "interest", "into", "invest",
    "invite", "involve", "iron", "island", "isolate", "issue", "item",
    "ivory", "jacket", "jaguar", "jar", "jazz", "jealous", "jeans",
    "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge",
    "juice", "jump", "jungle", "junior", "junk", "just", "kangaroo",
    "keen", "keep", "ketchup", "key", "kick", "kid", "kidney",
    "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten",
    "kiwi", "knee", "knife", "knock", "know", "lab", "label", "labor",
    "ladder", "lady", "lake", "lamp", "language", "laptop", "large",
    "later", "latin", "laugh", "laundry", "lava", "law", "lawn",
    "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave",
    "lecture", "left", "leg", "legal", "legend", "leisure", "lemon",
    "lend", "length", "lens", "leopard", "lesson", "letter", "level",
    "liar", "liberty", "library", "license", "life", "lift", "light",
    "like", "limb", "limit", "link", "lion", "liquid", "list",
    "little", "live", "lizard", "load", "loan", "lobster", "local",
    "lock", "logic", "lonely", "long", "loop", "lottery", "loud",
    "lounge", "love", "loyal", "lucky", "luggage", "lumber", "lunar",
    "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet",
    "maid", "mail", "main", "major", "make", "mammal", "man", "manage",
    "mandate", "mango", "mansion", "manual", "maple", "marble",
    "march", "margin", "marine", "market", "marriage", "mask", "mass",
    "master", "match", "material", "math", "matrix", "matter",
    "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic",
    "medal", "media", "melody", "melt", "member", "memory", "mention",
    "menu", "mercy", "merge", "merit", "merry", "mesh", "message",
    "metal", "method", "middle", "midnight", "milk", "million",
    "mimic", "mind", "minimum", "minor", "minute", "miracle", "mirror",
    "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile",
    "model", "modify", "mom", "moment", "monitor", "monkey", "monster",
    "month", "moon", "moral", "more", "morning", "mosquito", "mother",
    "motion", "motor", "mountain", "mouse", "move", "movie", "much",
    "muffin", "mule", "multiply", "muscle", "museum", "mushroom",
    "music", "must", "mutual", "myself", "mystery", "myth", "naive",
    "name", "napkin", "narrow", "nasty", "nation", "nature", "near",
    "neck", "need", "negative", "neglect", "neither", "nephew", "nerve",
    "nest", "net", "network", "neutral", "never", "news", "next",
    "nice", "night", "noble", "noise", "nominee", "noodle", "normal",
    "north", "nose", "notable", "note", "nothing", "notice", "novel",
    "now", "nuclear", "number", "nurse", "nut", "oak", "obey",
    "object", "oblige", "obscure", "observe", "obtain", "obvious",
    "occur", "ocean", "october", "odor", "off", "offer", "office",
    "often", "oil", "okay", "old", "olive", "olympic", "omit", "once",
    "one", "onion", "online", "only", "open", "opera", "opinion",
    "oppose", "option", "orange", "orbit", "orchard", "order",
    "ordinary", "organ", "orient", "original", "orphan", "ostrich",
    "other", "outdoor", "outer", "output", "outside", "oval", "oven",
    "over", "own", "owner", "oxygen", "oyster", "ozone", "pact",
    "paddle", "page", "pair", "palace", "palm", "panda", "panel",
    "panic", "panther", "paper", "parade", "parent", "park", "parrot",
    "party", "pass", "patch", "path", "patient", "patrol", "pattern",
    "pause", "pave", "payment", "peace", "peanut", "pear", "peasant",
    "pelican", "pen", "penalty", "pencil", "people", "pepper",
    "perfect", "permit", "person", "pet", "phone", "photo", "phrase",
    "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon",
    "pill", "pilot", "pink", "pioneer", "pipe", "pistol", "pitch",
    "pizza", "place", "planet", "plastic", "plate", "play", "please",
    "pledge", "pluck", "plug", "plunge", "poem", "poet", "point",
    "polar", "pole", "police", "pond", "pony", "pool", "popular",
    "portion", "position", "possible", "post", "potato", "pottery",
    "poverty", "powder", "power", "practice", "praise", "predict",
    "prefer", "prepare", "present", "pretty", "prevent", "price",
    "pride", "primary", "print", "priority", "prison", "private",
    "prize", "problem", "process", "produce", "profit", "program",
    "project", "promote", "proof", "property", "prosper", "protect",
    "proud", "provide", "public", "pudding", "pull", "pulp", "pulse",
    "pumpkin", "punch", "pupil", "puppy", "purchase", "purity",
    "purpose", "purse", "push", "put", "puzzle", "pyramid", "quality",
    "quantum", "quarter", "question", "quick", "quit", "quiz", "quote",
    "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail",
    "rain", "raise", "rally", "ramp", "ranch", "random", "range",
    "rapid", "rare", "rate", "rather", "raven", "raw", "razor",
    "ready", "real", "reason", "rebel", "rebuild", "recall", "receive",
    "recipe", "record", "recycle", "reduce", "reflect", "reform",
    "refuse", "region", "regret", "regular", "reject", "relax",
    "release", "relief", "rely", "remain", "remember", "remind",
    "remove", "render", "renew", "rent", "reopen", "repair", "repeat",
    "replace", "report", "require", "rescue", "resemble", "resist",
    "resource", "response", "result", "retire", "retreat", "return",
    "reunion", "reveal", "review", "reward", "rhythm", "rib", "ribbon",
    "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring",
    "riot", "ripple", "risk", "ritual", "rival", "river", "road",
    "roast", "robot", "robust", "rocket", "romance", "roof", "rookie",
    "room", "rose", "rotate", "rough", "round", "route", "royal",
    "rubber", "rude", "rug", "rule", "run", "runway", "rural", "sad",
    "saddle", "sadness", "safe", "sail", "salad", "salmon", "salon",
    "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi",
    "sauce", "sausage", "save", "say", "scale", "scan", "scare",
    "scatter", "scene", "scheme", "school", "science", "scissors",
    "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea",
    "search", "season", "seat", "second", "secret", "section",
    "security", "seed", "seek", "segment", "select", "sell", "seminar",
    "senior", "sense", "sentence", "series", "service", "session",
    "settle", "setup", "seven", "shadow", "shaft", "shallow", "share",
    "shed", "shell", "sheriff", "shield", "shift", "shine", "ship",
    "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder",
    "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick",
    "side", "siege", "sight", "sign", "silent", "silk", "silly",
    "silver", "similar", "simple", "since", "sing", "siren", "sister",
    "situate", "six", "size", "skate", "sketch", "ski", "skill",
    "skin", "skirt", "skull", "slab", "slam", "sleep", "slender",
    "slice", "slide", "slight", "slim", "slogan", "slot", "slow",
    "slush", "small", "smart", "smile", "smoke", "smooth", "snack",
    "snake", "snap", "sniff", "snow", "soap", "soccer", "social",
    "sock", "soda", "soft", "solar", "soldier", "solid", "solution",
    "solve", "someone", "song", "soon", "sorry", "sort", "soul",
    "sound", "soup", "source", "south", "space", "spare", "spatial",
    "spawn", "speak", "special", "speed", "spell", "spend", "sphere",
    "spice", "spider", "spike", "spin", "spirit", "split", "spoil",
    "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring",
    "spy", "square", "squeeze", "squirrel", "stable", "stadium",
    "staff", "stage", "stairs", "stamp", "stand", "start", "state",
    "stay", "steak", "steel", "stem", "step", "stereo", "stick",
    "still", "sting", "stock", "stomach", "stone", "stool", "story",
    "stove", "strategy", "street", "strike", "strong", "struggle",
    "student", "stuff", "stumble", "style", "subject", "submit",
    "subway", "success", "such", "sudden", "suffer", "sugar", "suggest",
    "suit", "summer", "sun", "sunny", "sunset", "super", "supply",
    "supreme", "sure", "surface", "surge", "surprise", "surround",
    "survey", "suspect", "sustain", "swallow", "swamp", "swap",
    "swarm", "swear", "sweet", "swift", "swim", "swing", "switch",
    "sword", "symbol", "symptom", "syrup", "system", "table", "tackle",
    "tag", "tail", "talent", "talk", "tank", "tape", "target", "task",
    "taste", "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant",
    "tennis", "tent", "term", "test", "text", "thank", "that", "theme",
    "then", "theory", "there", "they", "thing", "this", "thought",
    "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide",
    "tiger", "tilt", "timber", "time", "tiny", "tip", "tired", "tissue",
    "title", "toast", "tobacco", "today", "toddler", "toe", "together",
    "toilet", "token", "tomato", "tomorrow", "tone", "tongue", "tonight",
    "tool", "tooth", "top", "topic", "topple", "torch", "tornado",
    "tortoise", "toss", "total", "tourist", "toward", "tower", "town",
    "toy", "track", "trade", "traffic", "tragic", "train", "transfer",
    "trap", "trash", "travel", "tray", "treat", "tree", "trend",
    "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy",
    "trouble", "truck", "true", "truly", "trumpet", "trust", "truth",
    "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey",
    "turn", "turtle", "twelve", "twenty", "twice", "twin", "twist",
    "two", "type", "typical", "ugly", "umbrella", "unable", "unaware",
    "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy",
    "uniform", "unique", "unit", "universe", "unknown", "unlock",
    "until", "unusual", "unveil", "update", "upgrade", "uphold",
    "upon", "upper", "upset", "urban", "urge", "usage", "use", "used",
    "useful", "useless", "usual", "utility", "vacant", "vacuum",
    "vague", "valid", "valley", "valve", "van", "vanish", "vapor",
    "various", "vast", "vault", "vehicle", "velvet", "vendor",
    "venture", "venue", "verb", "verify", "version", "very", "vessel",
    "veteran", "viable", "vibrant", "vicious", "victory", "video",
    "view", "village", "vintage", "violin", "virtual", "virus",
    "visa", "visit", "visual", "vital", "vivid", "vocal", "voice",
    "void", "volcano", "volume", "vote", "voyage", "wage", "wagon",
    "wait", "walk", "wall", "walnut", "want", "warfare", "warm",
    "warrior", "wash", "wasp", "waste", "water", "wave", "way",
    "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding",
    "weekend", "weird", "welcome", "west", "wet", "whale", "what",
    "wheat", "wheel", "when", "where", "whip", "whisper", "wide",
    "width", "wife", "wild", "will", "win", "window", "wine", "wing",
    "wink", "winner", "winter", "wire", "wisdom", "wise", "wish",
    "witness", "wolf", "woman", "wonder", "wood", "wool", "word",
    "work", "world", "worry", "worth", "wrap", "wreck", "wrestle",
    "wrist", "write", "wrong", "yard", "year", "yellow", "you",
    "young", "youth", "zebra", "zero", "zone", "zoo",
}

# Regex patterns
RE_HEX_KEY = re.compile(r'\b([0-9a-fA-F]{64})\b')
RE_WIF = re.compile(r'\b([5KL][1-9A-HJ-NP-Za-km-z]{50,51})\b')
RE_ETH_ADDR = re.compile(r'\b(0x[0-9a-fA-F]{40})\b')
RE_BTC_ADDR = re.compile(r'\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,62})\b')
RE_SOL_KEY = re.compile(r'\b([1-9A-HJ-NP-Za-km-z]{87,88})\b')


def is_binary(path: Path) -> bool:
    """Quick check: read first 512 bytes, count non-printable chars."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(512)
        if not chunk:
            return False
        non_printable = sum(1 for b in chunk if b < 9 or (13 < b < 32) or b > 126)
        return (non_printable / len(chunk)) > BINARY_RATIO
    except Exception:
        return True


def extract_seed_phrases(text: str) -> List[str]:
    """Find BIP39 seed phrases (12 or 24 words) in text."""
    words = text.lower().split()
    found = []
    i = 0
    while i < len(words):
        word = words[i].strip(".,;:!?\"'()[]{}")
        if word in BIP39_WORDS:
            # Try to build a phrase
            phrase_words = [word]
            j = i + 1
            while j < len(words) and j - i < 24:
                w = words[j].strip(".,;:!?\"'()[]{}")
                if w in BIP39_WORDS:
                    phrase_words.append(w)
                    j += 1
                else:
                    break
            if len(phrase_words) in (12, 24):
                found.append(" ".join(phrase_words))
            i = j
        else:
            i += 1
    # Deduplicate
    return list(dict.fromkeys(found))


def scan_file(path: Path) -> Optional[dict]:
    """Extract crypto material from a single file. Returns findings dict or None."""
    try:
        size = os.path.getsize(path)
        if size > MAX_FILE_SIZE or size == 0:
            return None
        if is_binary(path):
            return None
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except Exception:
        return None

    if not text.strip():
        return None

    findings: dict = {
        "wallet": {"wifs": [], "hex_keys": [], "seed_phrases": []},
        "derived_addresses": [],
    }

    # HEX private keys
    hex_keys = []
    for m in RE_HEX_KEY.finditer(text):
        hk = m.group(1)
        # Filter junk hex (all zeros, all Fs, low entropy)
        hk_lower = hk.lower()
        if hk_lower in ("0" * 64, "f" * 64):
            continue
        if len(set(hk_lower)) <= 4:
            continue
        if hk_lower.count("0") > 48:
            continue
        hex_keys.append(hk)

    # WIF keys
    wifs = []
    for m in RE_WIF.finditer(text):
        w = m.group(1)
        # Basic WIF validation: length check
        if 50 <= len(w) <= 52:
            wifs.append(w)

    # Seed phrases
    seeds = extract_seed_phrases(text)

    # Ethereum addresses found directly
    eth_addrs = list(dict.fromkeys(m.group(1) for m in RE_ETH_ADDR.finditer(text)))

    # Filter: addresses that appear alongside keys are likely the derived ones
    findings["wallet"]["hex_keys"] = list(dict.fromkeys(hex_keys))
    findings["wallet"]["wifs"] = list(dict.fromkeys(wifs))
    findings["wallet"]["seed_phrases"] = list(dict.fromkeys(seeds))

    # Add standalone addresses (might be watch-only or contract refs)
    for addr in eth_addrs[:20]:  # cap per file
        findings["derived_addresses"].append(
            {"chain": "eth", "address": addr, "from": "direct_scan"}
        )

    # Check if we found anything
    if not (hex_keys or wifs or seeds):
        return None

    findings["confidence"] = "high" if (hex_keys or wifs or seeds) else "medium"
    return findings


def should_scan(path: Path) -> bool:
    """Check if file should be scanned based on name/extension."""
    name = path.name.lower()
    if name.startswith("."):
        # Still scan .env files and hidden files in storage
        if not any(p in name for p in ("env", "wallet", "key", "seed", "secret")):
            return False
    # Always scan these patterns
    scan_patterns = (
        ".json", ".txt", ".env", ".dat", ".keystore",
        "wallet", "seed", "key", "backup", "secret", "mnemonic",
        "private", "crypto", "metamask", "trust", "phantom",
        "solana", "ethereum", "bitcoin",
    )
    return any(p in name for p in scan_patterns) or any(
        name.endswith(ext) for ext in (".json", ".txt", ".dat", ".keystore", ".env")
    )


def scan_directory(root: Path, max_depth: int = 99) -> Tuple[int, int, List[dict]]:
    """Recursively scan a directory. Returns (files_scanned, wallets_found, findings)."""
    files_scanned = 0
    wallets_found = 0
    all_findings: List[dict] = []

    try:
        for entry in os.scandir(root):
            try:
                path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    name = entry.name
                    if name in SKIP_DIRS or name.startswith("."):
                        continue
                    if max_depth > 0:
                        sub_files, sub_wallets, sub_findings = scan_directory(
                            path, max_depth - 1
                        )
                        files_scanned += sub_files
                        wallets_found += sub_wallets
                        all_findings.extend(sub_findings)
                elif entry.is_file(follow_symlinks=False):
                    if not should_scan(path):
                        continue
                    findings = scan_file(path)
                    files_scanned += 1
                    if findings:
                        wallets_found += 1
                        all_findings.append({
                            "file": str(path),
                            "findings": findings,
                            "size": os.path.getsize(path),
                        })
                        # Print each finding as we go
                        n_keys = (len(findings["wallet"]["hex_keys"]) +
                                  len(findings["wallet"]["wifs"]) +
                                  len(findings["wallet"]["seed_phrases"]))
                        rel = str(path).replace(str(HOME), "~")
                        print(f"  {OK} {GOLD}{n_keys}{RST} keys  {DIM}{rel}{RST}")
            except (PermissionError, OSError):
                continue
    except (PermissionError, OSError):
        pass

    return files_scanned, wallets_found, all_findings


def feed_pipeline(findings: List[dict], dry_run: bool = False) -> int:
    """Write findings to crypto_scanner_memory.jsonl and trigger balance checks."""
    memory_file = HOME / "crypto_scanner_memory.jsonl"
    now_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    written = 0

    for f in findings:
        rec = {
            "findings": f["findings"],
            "source": "android_scan",
            "source_uri": f"file://{f['file']}",
            "timestamp": now_ts,
        }
        if dry_run:
            written += 1
            continue
        try:
            with open(memory_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")
            written += 1
        except OSError:
            pass

    # Trigger balance checking
    if not dry_run and written > 0:
        try:
            import crypto_scanner as cs
            addr_map: Dict[str, List[str]] = {}
            for f in findings:
                for d in f["findings"].get("derived_addresses", []):
                    addr_map.setdefault(d.get("chain", "eth"), []).append(d.get("address", ""))
            if addr_map:
                cs.queue_balances(addr_map)
        except Exception:
            pass

    return written


def email_results(findings: List[dict], stats: dict) -> None:
    """Send findings summary via email."""
    try:
        from daily_funded_report import smtp_creds, send_email
        creds = smtp_creds()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        body_lines = [
            "=" * 60,
            "ANDROID WALLET SCAN RESULTS",
            f"Scanned: {now}",
            f"Files scanned: {stats['files']}",
            f"Wallets found: {stats['wallets']}",
            f"Pipeline records written: {stats['written']}",
            "=" * 60,
            "",
        ]
        for f in findings[:50]:  # cap email to 50 findings
            body_lines.append(f"FILE: {f['file']}")
            wallet = f["findings"]["wallet"]
            if wallet["hex_keys"]:
                body_lines.append(f"  HEX keys: {len(wallet['hex_keys'])}")
            if wallet["wifs"]:
                body_lines.append(f"  WIF keys: {len(wallet['wifs'])}")
            if wallet["seed_phrases"]:
                body_lines.append(f"  Seeds: {len(wallet['seed_phrases'])}")
            body_lines.append("")
        if len(findings) > 50:
            body_lines.append(f"... +{len(findings) - 50} more files")
        body = "\n".join(body_lines)
        send_email(
            creds,
            subject=f"[ANDROID SCAN] {stats['wallets']} wallets found on device · {now}",
            body=body,
        )
        print(f"\n  {OK} Email sent to {creds.get('REPORT_EMAIL')}")
    except Exception as exc:
        print(f"\n  {ERR} Email failed: {exc}")


def main():
    ap = argparse.ArgumentParser(description="Android Wallet Scanner")
    ap.add_argument("--email", action="store_true", help="email results")
    ap.add_argument("--dry-run", action="store_true", help="scan only, don't write")
    ap.add_argument("--paths", nargs="*", help="specific paths to scan")
    args = ap.parse_args()

    if args.paths:
        scan_roots = [Path(p) for p in args.paths]
    else:
        scan_roots = [
            HOME / "storage" / "shared",
            HOME / "storage" / "downloads",
            HOME / "storage" / "dcim",
            HOME / "storage" / "documents",
            HOME / "downloads",
            HOME / "inbox",
            HOME / "backups",
            HOME,  # home last, limited depth
        ]

    print(f"\n{ORANGE}{BOLD}╔{'═'*58}╗{RST}")
    print(f"{ORANGE}{BOLD}║{RST}  {BOLD}ANDROID WALLET SCANNER{RST}" + " " * 35 + f"{ORANGE}{BOLD}║{RST}")
    print(f"{ORANGE}{BOLD}╚{'═'*58}╝{RST}")
    print(f"  {DIM}Scanning device for crypto wallets...{RST}\n")

    total_files = 0
    total_wallets = 0
    all_findings: List[dict] = []

    t0 = time.time()
    for root in scan_roots:
        if not root.exists():
            print(f"  {DIM}skip: {root} (not found){RST}")
            continue
        depth = MAX_DEPTH_HOME if root == HOME else 99
        label = str(root).replace(str(HOME), "~")
        print(f"  {CYAN}▶{RST} {BOLD}{label}{RST}")
        files, wallets, findings = scan_directory(root, max_depth=depth)
        total_files += files
        total_wallets += wallets
        all_findings.extend(findings)
        print()

    elapsed = time.time() - t0

    # ── Summary ─────────────────────────────────────────────────────
    print(f"{ORANGE}{'─'*60}{RST}")
    print(f"  {BOLD}SCAN COMPLETE{RST}  ({elapsed:.1f}s)")
    print(f"  Files scanned:  {GOLD}{total_files}{RST}")
    print(f"  Wallets found:  {GREEN}{total_wallets}{RST}")
    total_keys = sum(
        len(f["findings"]["wallet"]["hex_keys"])
        + len(f["findings"]["wallet"]["wifs"])
        + len(f["findings"]["wallet"]["seed_phrases"])
        for f in all_findings
    )
    print(f"  Keys extracted: {GOLD}{total_keys}{RST}")

    # Feed pipeline
    if all_findings:
        written = feed_pipeline(all_findings, dry_run=args.dry_run)
        print(f"  Pipeline write: {GREEN if written else DIM}{written} records{RST}")
    else:
        written = 0

    stats = {"files": total_files, "wallets": total_wallets, "written": written}

    # Email
    if args.email and all_findings:
        email_results(all_findings, stats)

    print(f"{ORANGE}{'─'*60}{RST}")
    if args.dry_run:
        print(f"  {GOLD}DRY RUN — no files written{RST}")
    print()


if __name__ == "__main__":
    main()
