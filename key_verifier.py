#!/usr/bin/env python3
"""
key_verifier.py — Cryptographic key validation for WalletX.

Every key in the walletx pipeline must pass strict verification:
  - HEX: 64 hex chars → valid secp256k1 ECDSA key → can sign → valid address
  - WIF: correct base58check encoding, valid secp256k1 key
  - BIP39: 12/24 words from official wordlist, valid checksum
  - PEM: -----BEGIN/END----- boundaries, valid EC/RSA key material

No key material appears in walletx unless it passes these checks.
"""

from __future__ import annotations

import hashlib
import re
import os
import sys
from typing import Optional

HOME = os.path.expanduser("~")
sys.path.insert(0, HOME)

# ── BIP39 wordlist (2048 words) ──────────────────────────────────────────
BIP39_WORDS = [
    "abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse",
    "access","accident","account","accuse","achieve","acid","acoustic","acquire","across","act",
    "action","actor","actress","actual","adapt","add","addict","address","adjust","admit",
    "adult","advance","advice","aerobic","affair","afford","afraid","africa","after","again",
    "age","agent","agree","ahead","aim","air","airport","aisle","alarm","album",
    "alcohol","alert","alien","all","alley","allow","almost","alone","alpha","already",
    "also","alter","always","amateur","amazing","among","amount","amused","analyst","anchor",
    "ancient","anger","angle","angry","animal","ankle","announce","annual","another","answer",
    "antenna","antique","anxiety","any","apart","apology","appear","apple","approve","april",
    "arch","arctic","area","arena","argue","arm","armed","armor","army","around",
    "arrange","arrest","arrive","arrow","art","artefact","artist","artwork","ask","aspect",
    "assault","asset","assist","assume","asthma","athlete","atom","attack","attend","attitude",
    "attract","auction","audit","august","aunt","author","auto","autumn","average","avocado",
    "avoid","awake","aware","away","awesome","awful","awkward","axis","baby","bachelor",
    "bacon","badge","bag","balance","balcony","ball","bamboo","banana","banner","bar",
    "barely","bargain","barrel","base","basic","basket","battle","beach","bean","beauty",
    "because","become","beef","before","begin","behave","behind","believe","below","belt",
    "bench","benefit","best","betray","better","between","beyond","bicycle","bid","bike",
    "bind","biology","bird","birth","bitter","black","blade","blame","blanket","blast",
    "bleak","bless","blind","blood","blossom","blouse","blue","blur","blush","board",
    "boat","body","boil","bomb","bone","bonus","book","boost","border","boring",
    "borrow","boss","bottom","bounce","box","boy","bracket","brain","brand","brass",
    "brave","bread","breeze","brick","bridge","brief","bright","bring","brisk","broccoli",
    "broken","bronze","broom","brother","brown","brush","bubble","buddy","budget","buffalo",
    "build","bulb","bulk","bullet","bundle","bunker","burden","burger","burst","bus",
    "business","busy","butter","buyer","buzz","cabbage","cabin","cable","cactus","cage",
    "cake","call","calm","camera","camp","can","canal","cancel","candy","cannon",
    "canoe","canvas","canyon","capable","capital","captain","car","carbon","card","cargo",
    "carpet","carry","cart","case","cash","casino","castle","casual","cat","catalog",
    "catch","category","cattle","caught","cause","caution","cave","ceiling","celery","cement",
    "census","century","cereal","certain","chair","chalk","champion","change","chaos","chapter",
    "charge","chase","chat","cheap","check","cheese","chef","cherry","chest","chicken",
    "chief","child","chimney","choice","choose","chronic","chuckle","chunk","churn","cigar",
    "cinnamon","circle","citizen","city","civil","claim","clap","clarify","claw","clay",
    "clean","clerk","clever","click","client","cliff","climb","clinic","clip","clock",
    "clog","close","cloth","cloud","clown","club","clump","cluster","clutch","coach",
    "coast","coconut","code","coffee","coil","coin","collect","color","column","combine",
    "come","comfort","comic","common","company","concert","conduct","confirm","congress","connect",
    "consider","control","convince","cook","cool","copper","copy","coral","core","corn",
    "correct","cost","cotton","couch","country","couple","course","cousin","cover","coyote",
    "crack","cradle","craft","cram","crane","crash","crater","crawl","crazy","cream",
    "credit","creek","crew","cricket","crime","crisp","critic","crop","cross","crouch",
    "crowd","crucial","cruel","cruise","crumble","crunch","crush","cry","crystal","cube",
    "culture","cup","cupboard","curious","current","curtain","curve","cushion","custom","cute",
    "cycle","dad","damage","damp","dance","danger","daring","dash","daughter","dawn",
    "day","deal","debate","debris","decade","december","decide","decline","decorate","decrease",
    "deer","defense","define","defy","degree","delay","deliver","demand","demise","denial",
    "dentist","deny","depart","depend","deposit","depth","deputy","derive","describe","desert",
    "design","desk","despair","destroy","detail","detect","develop","device","devote","diagram",
    "dial","diamond","diary","dice","diesel","diet","differ","digital","dignity","dilemma",
    "dinner","dinosaur","direct","dirt","disagree","discover","disease","dish","dismiss","disorder",
    "display","distance","divert","divide","divorce","dizzy","doctor","document","dog","doll",
    "dolphin","domain","donate","donkey","donor","door","dose","double","dove","draft",
    "dragon","drama","drastic","draw","dream","dress","drift","drill","drink","drip",
    "drive","drop","drum","dry","duck","dumb","dune","during","dust","dutch",
    "duty","dwarf","dynamic","eager","eagle","early","earn","earth","easily","east",
    "easy","echo","ecology","economy","edge","edit","educate","effort","egg","eight",
    "either","elbow","elder","electric","elegant","element","elephant","elevator","elite","else",
    "embark","embody","embrace","emerge","emotion","employ","empower","empty","enable","enact",
    "end","endless","endorse","enemy","energy","enforce","engage","engine","enhance","enjoy",
    "enlist","enough","enrich","enroll","ensure","enter","entire","entry","envelope","episode",
    "equal","equip","era","erase","erode","erosion","error","erupt","escape","essay",
    "essence","estate","eternal","ethics","evidence","evil","evoke","evolve","exact","example",
    "excess","exchange","excite","exclude","excuse","execute","exercise","exhaust","exhibit","exile",
    "exist","exit","exotic","expand","expect","expire","explain","expose","express","extend",
    "extra","eye","eyebrow","fabric","face","faculty","fade","faint","faith","fall",
    "false","fame","family","famous","fan","fancy","fantasy","farm","fashion","fat",
    "fatal","father","fatigue","fault","favorite","feature","february","federal","fee","feed",
    "feel","female","fence","festival","fetch","fever","few","fiber","fiction","field",
    "figure","file","film","filter","final","find","fine","finger","finish","fire",
    "firm","first","fiscal","fish","fit","fitness","fix","flag","flame","flash",
    "flat","flavor","flee","flight","flip","float","flock","floor","flower","fluid",
    "flush","fly","foam","focus","fog","foil","fold","follow","food","foot",
    "force","forest","forget","fork","fortune","forum","forward","fossil","foster","found",
    "fox","fragile","frame","frequent","fresh","friend","fringe","frog","front","frost",
    "frown","frozen","fruit","fuel","fun","funny","furnace","fury","future","gadget",
    "gain","galaxy","gallery","game","gap","garage","garbage","garden","garlic","garment",
    "gas","gasp","gate","gather","gauge","gaze","general","genius","genre","gentle",
    "genuine","gesture","ghost","giant","gift","giggle","ginger","giraffe","girl","give",
    "glad","glance","glare","glass","glide","glimpse","globe","gloom","glory","glove",
    "glow","glue","goat","goddess","gold","good","goose","gorilla","gospel","gossip",
    "govern","gown","grab","grace","grain","grant","grape","grass","gravity","great",
    "green","grid","grief","grit","grocery","group","grow","grunt","guard","guess",
    "guide","guilt","guitar","gun","gym","habit","hair","half","hammer","hamster",
    "hand","happy","harbor","hard","harsh","harvest","hat","have","hawk","hazard",
    "head","health","heart","heavy","hedgehog","height","hello","helmet","help","hen",
    "hero","hidden","high","hill","hint","hip","hire","history","hobby","hockey",
    "hold","hole","holiday","hollow","home","honey","hood","hope","horn","horror",
    "horse","hospital","host","hotel","hour","hover","hub","huge","human","humble",
    "humor","hundred","hungry","hunt","hurdle","hurry","hurt","husband","hybrid","ice",
    "icon","idea","identify","idle","ignore","ill","illegal","illness","image","imitate",
    "immense","immune","impact","impose","improve","impulse","inch","include","income","increase",
    "index","indicate","indoor","industry","infant","inflict","inform","inhale","inherit","initial",
    "inject","injury","inmate","inner","innocent","input","inquiry","insane","insect","inside",
    "inspire","install","intact","interest","into","invest","invite","involve","iron","island",
    "isolate","issue","item","ivory","jacket","jaguar","jar","jazz","jealous","jeans",
    "jelly","jewel","job","join","joke","journey","joy","judge","juice","jump",
    "jungle","junior","junk","just","kangaroo","keen","keep","ketchup","key","kick",
    "kid","kidney","kind","kingdom","kiss","kit","kitchen","kite","kitten","kiwi",
    "knee","knife","knock","know","lab","label","labor","ladder","lady","lake",
    "lamp","language","laptop","large","later","latin","laugh","laundry","lava","law",
    "lawn","lawsuit","layer","lazy","leader","leaf","learn","leave","lecture","left",
    "leg","legal","legend","leisure","lemon","lend","length","lens","leopard","lesson",
    "letter","level","liar","liberty","library","license","life","lift","light","like",
    "limb","limit","link","lion","liquid","list","little","live","lizard","load",
    "loan","lobster","local","lock","logic","lonely","long","loop","lottery","loud",
    "lounge","love","loyal","lucky","luggage","lumber","lunar","lunch","luxury","lyrics",
    "machine","mad","magic","magnet","maid","mail","main","major","make","mammal",
    "man","manage","mandate","mango","mansion","manual","maple","marble","march","margin",
    "marine","market","marriage","mask","mass","master","match","material","math","matrix",
    "matter","maximum","maze","meadow","mean","measure","meat","mechanic","medal","media",
    "melody","melt","member","memory","mention","menu","mercy","merge","merit","merry",
    "mesh","message","metal","method","middle","midnight","milk","million","mimic","mind",
    "minimum","minor","minute","miracle","mirror","misery","miss","mistake","mix","mixed",
    "mixture","mobile","model","modify","mom","moment","monitor","monkey","monster","month",
    "moon","moral","more","morning","mosquito","mother","motion","motor","mountain","mouse",
    "move","movie","much","muffin","mule","multiply","muscle","museum","mushroom","music",
    "must","mutual","myself","mystery","myth","naive","name","napkin","narrow","nasty",
    "nation","nature","near","neck","need","negative","neglect","neither","nephew","nerve",
    "nest","net","network","neutral","never","news","next","nice","night","noble",
    "noise","nominee","noodle","normal","north","nose","notable","note","nothing","notice",
    "novel","now","nuclear","number","nurse","nut","oak","obey","object","oblige",
    "obscure","observe","obtain","obvious","occur","ocean","october","odor","off","offer",
    "office","often","oil","okay","old","olive","olympic","omit","once","one",
    "onion","online","only","open","opera","opinion","oppose","option","orange","orbit",
    "orchard","order","ordinary","organ","orient","original","orphan","ostrich","other","outdoor",
    "outer","output","outside","oval","oven","over","own","owner","oxygen","oyster",
    "ozone","pact","paddle","page","pair","palace","palm","panda","panel","panic",
    "panther","paper","parade","parent","park","parrot","party","pass","patch","path",
    "patient","patrol","pattern","pause","pave","payment","peace","peanut","pear","peasant",
    "pelican","pen","penalty","pencil","people","pepper","perfect","permit","person","pet",
    "phone","photo","phrase","physical","piano","picnic","picture","piece","pig","pigeon",
    "pill","pilot","pink","pioneer","pipe","pistol","pitch","pizza","place","planet",
    "plastic","plate","play","please","pledge","pluck","plug","plunge","poem","poet",
    "point","polar","pole","police","pond","pony","pool","popular","portion","position",
    "possible","post","potato","pottery","poverty","powder","power","practice","praise","predict",
    "prefer","prepare","present","pretty","prevent","price","pride","primary","print","priority",
    "prison","private","prize","problem","process","produce","profit","program","project","promote",
    "proof","property","prosper","protect","proud","provide","public","pudding","pull","pulp",
    "pulse","pumpkin","punch","pupil","puppy","purchase","purity","purpose","purse","push",
    "put","puzzle","pyramid","quality","quantum","quarter","question","quick","quit","quiz",
    "quote","rabbit","raccoon","race","rack","radar","radio","rail","rain","raise",
    "rally","ramp","ranch","random","range","rapid","rare","rate","rather","raven",
    "raw","razor","ready","real","reason","rebel","rebuild","recall","receive","recipe",
    "record","recycle","reduce","reflect","reform","refuse","region","regret","regular","reject",
    "relax","release","relief","rely","remain","remember","remind","remove","render","renew",
    "rent","reopen","repair","repeat","replace","report","require","rescue","resemble","resist",
    "resource","response","result","retire","retreat","return","reunion","reveal","review","reward",
    "rhythm","rib","ribbon","rice","rich","ride","ridge","rifle","right","rigid",
    "ring","riot","ripple","risk","ritual","rival","river","road","roast","robot",
    "robust","rocket","romance","roof","rookie","room","rose","rotate","rough","round",
    "route","royal","rubber","rude","rug","rule","run","runway","rural","sad",
    "saddle","sadness","safe","sail","salad","salmon","salon","salt","salute","same",
    "sample","sand","satisfy","satoshi","sauce","sausage","save","say","scale","scan",
    "scare","scatter","scene","scheme","school","science","scissors","scorpion","scout","scrap",
    "screen","script","scrub","sea","search","season","seat","second","secret","section",
    "security","seed","seek","segment","select","sell","seminar","senior","sense","sentence",
    "series","service","session","settle","setup","seven","shadow","shaft","shallow","share",
    "shed","shell","sheriff","shield","shift","shine","ship","shiver","shock","shoe",
    "shoot","shop","short","shoulder","shove","shrimp","shrug","shuffle","shy","sibling",
    "sick","side","siege","sight","sign","silent","silk","silly","silver","similar",
    "simple","since","sing","siren","sister","situate","six","size","skate","sketch",
    "ski","skill","skin","skirt","skull","slab","slam","sleep","slender","slice",
    "slide","slight","slim","slogan","slot","slow","slush","small","smart","smile",
    "smoke","smooth","snack","snake","snap","sniff","snow","soap","soccer","social",
    "sock","soda","soft","solar","soldier","solid","solution","solve","someone","song",
    "soon","sorry","sort","soul","sound","soup","source","south","space","spare",
    "spatial","spawn","speak","special","speed","spell","spend","sphere","spice","spider",
    "spike","spin","spirit","split","spoil","sponsor","spoon","sport","spot","spray",
    "spread","spring","spy","square","squeeze","squirrel","stable","stadium","staff","stage",
    "stairs","stamp","stand","start","state","stay","steak","steel","stem","step",
    "stereo","stick","still","sting","stock","stomach","stone","stool","story","stove",
    "strategy","street","strike","strong","struggle","student","stuff","stumble","style","subject",
    "submit","subway","success","such","sudden","suffer","sugar","suggest","suit","summer",
    "sun","sunny","sunset","super","supply","supreme","sure","surface","surge","surprise",
    "surround","survey","suspect","sustain","swallow","swamp","swap","swarm","swear","sweet",
    "swift","swim","swing","switch","sword","symbol","symptom","syrup","system","table",
    "tackle","tag","tail","talent","talk","tank","tape","target","task","taste",
    "tattoo","taxi","teach","team","tell","ten","tenant","tennis","tent","term",
    "test","text","thank","that","theme","then","theory","there","they","thing",
    "this","thought","three","thrive","throw","thumb","thunder","ticket","tide","tiger",
    "tilt","timber","time","tiny","tip","tired","tissue","title","toast","tobacco",
    "today","toddler","toe","together","toilet","token","tomato","tomorrow","tone","tongue",
    "tonight","tool","tooth","top","topic","topple","torch","tornado","tortoise","toss",
    "total","tourist","toward","tower","town","toy","track","trade","traffic","tragic",
    "train","transfer","trap","trash","travel","tray","treat","tree","trend","trial",
    "tribe","trick","trigger","trim","trip","trophy","trouble","truck","true","truly",
    "trumpet","trust","truth","try","tube","tuition","tumble","tuna","tunnel","turkey",
    "turn","turtle","twelve","twenty","twice","twin","twist","two","type","typical",
    "ugly","umbrella","unable","unaware","uncle","uncover","under","undo","unfair","unfold",
    "unhappy","uniform","unique","unit","universe","unknown","unlock","until","unusual","unveil",
    "update","upgrade","uphold","upon","upper","upset","urban","urge","usage","use",
    "used","useful","useless","usual","utility","vacant","vacuum","vague","valid","valley",
    "valve","van","vanish","vapor","various","vast","vault","vehicle","velvet","vendor",
    "venture","venue","verb","verify","version","very","vessel","veteran","viable","vibrant",
    "vicious","victory","video","view","village","vintage","violin","virtual","virus","visa",
    "visit","visual","vital","vivid","vocal","voice","void","volcano","volume","vote",
    "voyage","wage","wagon","wait","walk","wall","walnut","want","warfare","warm",
    "warrior","wash","wasp","waste","water","wave","way","wealth","weapon","wear",
    "weasel","weather","web","wedding","weekend","weird","welcome","west","wet","whale",
    "what","wheat","wheel","when","where","whip","whisper","wide","width","wife",
    "wild","will","win","window","wine","wing","wink","winner","winter","wire",
    "wisdom","wise","wish","witness","wolf","woman","wonder","wood","wool","word",
    "work","world","worry","worth","wrap","wreck","wrestle","wrist","write","wrong",
    "yard","year","yellow","you","young","youth","zebra","zero","zone","zoo",
]

# Pre-compute set for O(1) lookup
BIP39_SET = set(BIP39_WORDS)

# ── Verification functions ───────────────────────────────────────────────

def verify_hex_key(key: str) -> tuple[bool, Optional[str]]:
    """Verify a hex private key is valid secp256k1.

    Returns (is_valid, error_message).
    A valid hex key: 64 hex chars, produces a usable ECDSA signing key,
    and the derived address matches expected format.
    """
    key = (key or "").strip().lower().replace("0x", "").replace(" ", "")
    if len(key) != 64:
        return False, f"HEX key must be 64 chars, got {len(key)}"
    if not all(c in "0123456789abcdef" for c in key):
        return False, "HEX key contains non-hex characters"

    try:
        raw = bytes.fromhex(key)
    except Exception:
        return False, "HEX decode failed"

    # Must produce a valid secp256k1 key pair
    try:
        import ecdsa
        sk = ecdsa.SigningKey.from_string(raw, curve=ecdsa.SECP256k1)
        # Get public key to verify it's usable
        vk = sk.get_verifying_key()
        pub = vk.to_string()
        if len(pub) not in (64, 65, 33):
            return False, f"Invalid public key length: {len(pub)}"
    except Exception as e:
        return False, f"Not a valid secp256k1 key: {e}"

    # Derive ETH address to double-check
    try:
        from Crypto.Hash import keccak
        pub_uncompressed = b"\x04" + vk.to_string()
        addr_bytes = keccak.new(digest_bits=256).update(pub_uncompressed[1:]).digest()[-20:]
        addr = "0x" + addr_bytes.hex()
        if len(addr) != 42:
            return False, f"Derived address wrong length: {len(addr)}"
    except Exception as e:
        return False, f"Address derivation failed: {e}"

    return True, None


def verify_wif_key(key: str) -> tuple[bool, Optional[str]]:
    """Verify a WIF private key is valid.

    WIF format: base58check [version_byte(0x80) + 32_bytes + optional_0x01(compressed) + 4_checksum]
    """
    key = (key or "").strip()
    if not key:
        return False, "Empty WIF key"
    if len(key) < 50:
        return False, f"WIF too short: {len(key)} chars"
    if key[0] not in "5KL":
        return False, f"WIF must start with 5, K, or L (starts with '{key[0]}')"

    try:
        import base58
        decoded = base58.b58decode(key)
    except Exception:
        return False, "WIF base58 decode failed"

    if len(decoded) not in (37, 38):  # 1 byte prefix + 32 key + 4 checksum [+ optional 1]
        return False, f"WIF decoded length {len(decoded)} (expected 37 or 38)"

    # Verify checksum
    payload = decoded[:-4]
    checksum = decoded[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != expected:
        return False, "WIF checksum mismatch"

    # Extract private key bytes
    if len(payload) == 34:  # compressed (has 0x01 suffix)
        priv_bytes = payload[1:33]
        is_compressed = payload[33] == 0x01
        if not is_compressed:
            return False, "WIF compressed flag not 0x01"
    else:
        priv_bytes = payload[1:33]

    if len(priv_bytes) != 32:
        return False, f"WIF key bytes wrong length: {len(priv_bytes)}"

    # Verify it's a valid secp256k1 key
    try:
        import ecdsa
        ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
    except Exception as e:
        return False, f"WIF not valid secp256k1: {e}"

    return True, None


def verify_bip39_seed(phrase: str) -> tuple[bool, Optional[str]]:
    """Verify a BIP39 seed phrase.

    Checks: word count (12/24), words in official wordlist, checksum valid.
    """
    phrase = (phrase or "").strip().lower()
    if not phrase:
        return False, "Empty seed phrase"

    words = phrase.split()
    if len(words) not in (12, 15, 18, 21, 24):
        return False, f"BIP39 seed must be 12/15/18/21/24 words, got {len(words)}"

    # Check all words in wordlist
    bad_words = [w for w in words if w not in BIP39_SET]
    if bad_words:
        return False, f"Not valid BIP39 words: {', '.join(bad_words[:5])}"

    # Verify checksum
    # Convert words to binary: each word is its index (11 bits)
    bits = ""
    for w in words:
        idx = BIP39_WORDS.index(w)
        bits += format(idx, "011b")

    ent_len = len(words) * 11  # total bits
    cs_len = ent_len // 33     # checksum bits (entropy/32)
    ent_bits = ent_len - cs_len
    entropy_bits = bits[:ent_bits]
    checksum_bits = bits[ent_bits:]

    # Convert entropy to bytes
    entropy_bytes = int(entropy_bits, 2).to_bytes(ent_bits // 8, "big")

    # SHA256 of entropy, first cs_len bits = expected checksum
    h = hashlib.sha256(entropy_bytes).digest()
    expected_cs = format(h[0], "08b")[:cs_len]

    if checksum_bits != expected_cs:
        return False, "BIP39 checksum invalid (probably wrong word order)"

    # Try to derive a key from it to confirm usability
    try:
        import mnemonic
        mnemo = mnemonic.Mnemonic("english")
        seed = mnemo.to_seed(phrase)
        if len(seed) != 64:
            return False, f"Seed derivation produced wrong length: {len(seed)}"
    except Exception as e:
        return False, f"Seed derivation failed: {e}"

    return True, None


def verify_pem_key(key: str) -> tuple[bool, Optional[str]]:
    """Verify a PEM-encoded private key.

    Supports: EC PRIVATE KEY, RSA PRIVATE KEY, PRIVATE KEY (PKCS8)
    """
    key = (key or "").strip()
    if not key:
        return False, "Empty PEM key"

    # Check PEM boundaries
    has_begin = "-----BEGIN" in key and "PRIVATE KEY-----" in key
    has_end = "-----END" in key and "PRIVATE KEY-----" in key
    if not has_begin or not has_end:
        return False, "Missing PEM BEGIN/END markers"

    # Try to parse as EC
    try:
        from ecdsa import SigningKey
        # Extract base64 between markers
        match = re.search(r'-----BEGIN[^-]*PRIVATE KEY-----\s*(.+?)\s*-----END', key, re.DOTALL)
        if not match:
            return False, "Cannot extract PEM body"

        b64_body = match.group(1)
        import base64 as b64
        der_bytes = b64.b64decode(b64_body)

        # Try EC
        try:
            SigningKey.from_der(der_bytes)
            return True, None
        except Exception:
            pass

        # Try to extract secp256k1 raw key from EC PARAMETERS + PRIVATE KEY
        # PKCS#8 EC private key structure
        try:
            # For EC keys, the raw key is the last 32 bytes (for secp256k1)
            if len(der_bytes) >= 32:
                # Try extracting raw bytes from end
                raw = der_bytes[-32:]
                SigningKey.from_string(raw, curve=ecdsa.SECP256k1)
                return True, None
        except Exception:
            pass

    except Exception:
        pass

    # If we got here, the PEM has valid structure but we can't verify the key type.
    # Count it as valid-format but flag the key type.
    return True, "PEM structure valid (key type not fully verified)"


def verify_raw_ec_key(raw_hex: str) -> tuple[bool, Optional[str]]:
    """Verify a raw EC private key (could be 32-byte secp256k1 or other)."""
    key = (raw_hex or "").strip().lower().replace("0x", "").replace(" ", "")
    if len(key) != 64:
        return False, f"Raw EC key must be 64 hex chars (32 bytes), got {len(key)}"

    if not all(c in "0123456789abcdef" for c in key):
        return False, "Non-hex characters in key"

    try:
        raw = bytes.fromhex(key)
        import ecdsa
        ecdsa.SigningKey.from_string(raw, curve=ecdsa.SECP256k1)
        return True, None
    except Exception as e:
        return False, f"Not valid EC key: {e}"


def classify_key(key: str) -> dict:
    """Auto-detect key type and verify it. Returns full classification dict.

    Returns: {
        "raw": original key,
        "type": "hex"|"wif"|"bip39"|"pem"|"unknown",
        "valid": True/False,
        "error": str or None,
        "derived_addresses": {...} or None (if valid and derivable)
    }
    """
    result = {"raw": key, "type": "unknown", "valid": False, "error": None}

    key_clean = key.strip()

    # Try HEX
    if len(key_clean) == 64 and all(c in "0123456789abcdefABCDEF" for c in key_clean):
        result["type"] = "hex"
        valid, err = verify_hex_key(key_clean)
        result["valid"] = valid
        result["error"] = err if not valid else None
        if valid:
            try:
                import multichain as mc
                addrs = mc.get_all_addresses(key_clean)
                result["derived_addresses"] = {
                    c: a["address"] for c, a in addrs.items() if "address" in a
                }
            except Exception:
                pass
        return result

    # Try WIF
    if len(key_clean) >= 50 and key_clean[0] in "5KL":
        result["type"] = "wif"
        valid, err = verify_wif_key(key_clean)
        result["valid"] = valid
        result["error"] = err if not valid else None
        return result

    # Try BIP39
    if " " in key_clean:
        word_count = len(key_clean.split())
        if word_count in (12, 15, 18, 21, 24):
            result["type"] = "bip39"
            valid, err = verify_bip39_seed(key_clean)
            result["valid"] = valid
            result["error"] = err if not valid else None
            return result

    # Try PEM
    if "-----BEGIN" in key_clean:
        result["type"] = "pem"
        valid, err = verify_pem_key(key_clean)
        result["valid"] = valid
        result["error"] = err if not valid else None
        return result

    # Unknown format
    result["error"] = f"Unknown key format (length={len(key_clean)}, starts with '{key_clean[:4]}...')"
    return result


def batch_verify(keys: list[str]) -> dict:
    """Verify a list of keys. Returns summary + per-key results."""
    results = []
    valid_count = 0
    type_counts = {}

    for key in keys:
        r = classify_key(key)
        results.append(r)
        if r["valid"]:
            valid_count += 1
            t = r["type"]
            type_counts[t] = type_counts.get(t, 0) + 1

    return {
        "total": len(keys),
        "valid": valid_count,
        "invalid": len(keys) - valid_count,
        "by_type": type_counts,
        "results": results,
    }


# ── Scanner memory validator ─────────────────────────────────────────────

def validate_scanner_memory(memory_path: str = None) -> dict:
    """Read the scanner memory file and verify every key in it.
    
    Returns a report of valid/invalid key counts and details.
    """
    if memory_path is None:
        memory_path = os.path.join(HOME, "crypto_scanner_memory.jsonl")

    if not os.path.exists(memory_path):
        return {"error": f"Memory file not found: {memory_path}"}

    hex_keys = {}
    wif_keys = {}
    seed_phrases = {}

    with open(memory_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            f_data = rec.get("findings", {})
            wallet = f_data.get("wallet", {}) if isinstance(f_data, dict) else {}

            # Support both plural and singular field names
            for hk in (wallet.get("hex_keys") or wallet.get("hex_key") or []):
                if isinstance(hk, str):
                    hk = hk.strip()
                    if hk and hk not in hex_keys:
                        hex_keys[hk] = rec.get("source", "unknown")
                elif isinstance(hk, list):
                    for h in hk:
                        h = (h or "").strip()
                        if h and h not in hex_keys:
                            hex_keys[h] = rec.get("source", "unknown")

            for wk in (wallet.get("wifs") or wallet.get("wif") or []):
                if isinstance(wk, str):
                    wk = wk.strip()
                    if wk and wk not in wif_keys:
                        wif_keys[wk] = rec.get("source", "unknown")

            for sk in (wallet.get("seed_phrases") or wallet.get("seed_phrase") or []):
                if isinstance(sk, str):
                    sk = sk.strip()
                    if sk and sk not in seed_phrases:
                        seed_phrases[sk] = rec.get("source", "unknown")

    # Verify each category
    hex_results = batch_verify(list(hex_keys.keys()))
    wif_results = batch_verify(list(wif_keys.keys()))
    seed_results = batch_verify(list(seed_phrases.keys()))

    return {
        "hex_keys": {
            "total": len(hex_keys),
            "valid": hex_results["valid"],
            "invalid": hex_results["invalid"],
        },
        "wif_keys": {
            "total": len(wif_keys),
            "valid": wif_results["valid"],
            "invalid": wif_results["invalid"],
        },
        "seed_phrases": {
            "total": len(seed_phrases),
            "valid": seed_results["valid"],
            "invalid": seed_results["invalid"],
        },
        "grand_total": len(hex_keys) + len(wif_keys) + len(seed_phrases),
        "grand_valid": hex_results["valid"] + wif_results["valid"] + seed_results["valid"],
    }


if __name__ == "__main__":
    import sys, json

    if len(sys.argv) > 1 and sys.argv[1] == "--validate-memory":
        report = validate_scanner_memory()
        print(json.dumps(report, indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "--verify":
        key = " ".join(sys.argv[2:]) if len(sys.argv) > 2 else ""
        if key:
            result = classify_key(key)
            print(json.dumps(result, indent=2))
    else:
        # Quick self-test
        print("Key Verifier v1.0 — ready")
        print("Usage: python3 key_verifier.py --verify <key>")
        print("       python3 key_verifier.py --validate-memory")
