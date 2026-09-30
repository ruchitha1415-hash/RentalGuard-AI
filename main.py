
import os, json, time, math, random, secrets, re, sqlite3, hashlib

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()
PUBLIC_URL = os.getenv("PUBLIC_URL", "http://localhost:8000")
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

db = sqlite3.connect("trust.db", check_same_thread=False)
db.execute("create table if not exists contacts(k text, lid text)")
db.execute("create table if not exists photo_hashes(h text, lid text)")
db.execute("create table if not exists listing_texts(text_hash text, text_content text, lid text)")
db.commit()
links = {}

class Listing(BaseModel):
    text: str
    phone: str = ""
    upi: str = ""
    rent: float = 0
    bhk: int = 1
    locality: str = ""
    photos: list[str] = []

class LinkReq(BaseModel):
    address: str = ""
    claims: dict = {}

class Capture(BaseModel):
    lat: float
    lng: float
    timestamp: float
    readings: list
    frame: str

class ChatReq(BaseModel):
    chat: str
class PlanReq(BaseModel):
    score: int


def text_check(text):
    kws = [
        "advance", "abroad", "western union", "token amount",
        "hurry", "urgent", "no visit", "courier", "army",
        "whatsapp only", "many people interested", "pay now",
        "limited time", "send money", "deposit"
    ]

    low = text.lower()
    hits = [k for k in kws if k in low]

    score = max(0, 100 - len(hits) * 15)

    evidence = []

    for h in hits:
        evidence.append(f"Suspicious phrase detected: {h}")

    if len(text.strip()) < 30:
        score = max(0, score - 10)
        evidence.append("Listing description is unusually short")

    if not evidence:
        evidence.append("No obvious scam phrases detected locally")

    confidence = min(0.95, 0.4 + len(hits) * 0.08)

    return {
        "score": score,
        "confidence": confidence,
        "evidence": evidence
    }
LOCALITY_RENT = {
    "yelahanka": {1: 10000, 2: 16000, 3: 23000},
    "hebbal": {1: 12000, 2: 19000, 3: 28000},
    "whitefield": {1: 14000, 2: 22000, 3: 32000},
    "electronic city": {1: 9000, 2: 15000, 3: 22000},
    "indiranagar": {1: 18000, 2: 30000, 3: 45000},
}

def price_check(rent, bhk, locality):
    if rent <= 0:
        return {
            "score": 50,
            "confidence": 0.2,
            "evidence": ["Rent not given"]
        }

    area = locality.lower().strip()
    rents = LOCALITY_RENT.get(area)

    if not rents:
        return {
            "score": 60,
            "confidence": 0.2,
            "evidence": ["Locality not in local reference data"]
        }

    avg = rents.get(bhk)

    if not avg:
        return {
            "score": 60,
            "confidence": 0.2,
            "evidence": ["BHK type not in local reference data"]
        }

    ratio = rent / avg

    if ratio < 0.5:
        return {
            "score": 15,
            "confidence": 0.8,
            "evidence": [
                f"Rent ₹{rent:.0f} is far below the local reference ₹{avg}"
            ]
        }

    if ratio < 0.7:
        return {
            "score": 50,
            "confidence": 0.7,
            "evidence": [
                f"Rent ₹{rent:.0f} is noticeably below the local reference ₹{avg}"
            ]
        }

    if ratio > 1.8:
        return {
            "score": 55,
            "confidence": 0.6,
            "evidence": [
                f"Rent ₹{rent:.0f} is unusually high compared with the local reference ₹{avg}"
            ]
        }

    return {
        "score": 90,
        "confidence": 0.6,
        "evidence": [
            f"Rent ₹{rent:.0f} is within the local reference range around ₹{avg}"
        ]
    }
def text_reuse_check(text, lid):
    normalized = re.sub(r"\s+", " ", text.lower().strip())
    normalized = re.sub(r"[^a-z0-9 ]", "", normalized)

    if not normalized:
        return {
            "score": 50,
            "confidence": 0.2,
            "evidence": ["No listing text to compare"]
        }

    rows = db.execute(
        "select text_content, lid from listing_texts where lid != ?",
        (lid,)
    ).fetchall()

    best_similarity = 0
    best_lid = None

    from difflib import SequenceMatcher

    for old_text, old_lid in rows:
        similarity = SequenceMatcher(
            None, normalized, old_text
        ).ratio()

        if similarity > best_similarity:
            best_similarity = similarity
            best_lid = old_lid

    db.execute(
        "insert into listing_texts values (?, ?, ?)",
        (hashlib.sha256(normalized.encode()).hexdigest(), normalized, lid)
    )
    db.commit()

    if best_similarity >= 0.85:
        return {
            "score": 20,
            "confidence": 0.9,
            "evidence": [
                f"Listing text is highly similar to another listing ({best_similarity:.0%} similarity)"
            ]
        }

    if best_similarity >= 0.65:
        return {
            "score": 55,
            "confidence": 0.7,
            "evidence": [
                f"Listing text has substantial reuse similarity ({best_similarity:.0%})"
            ]
        }

    return {
        "score": 90,
        "confidence": 0.6,
        "evidence": ["No strong text-pattern reuse detected"]
    }
def metadata_check(text, phone, upi, rent, bhk, locality):
    score = 100
    evidence = []

    if not text.strip():
        score -= 25
        evidence.append("Listing description is missing")

    if not locality.strip():
        score -= 20
        evidence.append("Locality is missing")

    if rent <= 0:
        score -= 20
        evidence.append("Rent is missing or invalid")

    if bhk < 1 or bhk > 10:
        score -= 15
        evidence.append("BHK value looks invalid")

    if not phone.strip() and not upi.strip():
        score -= 15
        evidence.append("No phone or UPI contact supplied")

    if phone and len(re.sub(r"\D", "", phone)) < 10:
        score -= 10
        evidence.append("Phone number looks incomplete")

    score = max(0, score)

    if not evidence:
        evidence.append("Basic listing metadata looks complete")

    return {
        "score": score,
        "confidence": 0.8,
        "evidence": evidence
    }
def contact_check(phone, upi, lid):
    ev, worst = [], 100
    for k in [phone, upi]:
        if not k:
            continue
        if not db.execute("select 1 from contacts where k=? and lid=?", (k, lid)).fetchone():
            db.execute("insert into contacts values(?,?)", (k, lid)); db.commit()
        n = db.execute("select count(distinct lid) from contacts where k=?", (k,)).fetchone()[0]
        if n >= 3:
            worst = min(worst, 10); ev.append(f"{k} appears in {n} different listings")
        elif n == 2:
            worst = min(worst, 60); ev.append(f"{k} appears in 2 listings")
    return {"score": worst, "confidence": 0.7, "evidence": ev or ["Contact not seen in other listings"]}

def photo_check(photos, lid):
    if not photos:
        return {"score": 70, "confidence": 0.2, "evidence": ["No photos supplied"]}
    ev, score = [], 90
    for data in photos[:6]:
        try:
            raw = data.split(",", 1)[1] if "," in data else data
            h = hashlib.sha256(raw.encode()).hexdigest()
            old = db.execute("select distinct lid from photo_hashes where h=? and lid!=?", (h, lid)).fetchall()
            db.execute("insert into photo_hashes values(?,?)", (h, lid))
            db.commit()
            if old:
                score = min(score, 15)
                ev.append("A supplied photo exactly matches a photo used in another listing")
            else:
                ev.append("Photo has no exact duplicate in the local TrustLens history")
        except Exception:
            score = min(score, 50)
            ev.append("One photo could not be checked")
   
    return {"score": score, "confidence": 0.65, "evidence": ev}

@app.post("/analyze")
def analyze(l: Listing):
    lid = hashlib.md5(l.text.encode()).hexdigest()[:10]
    checks = {
    "metadata": metadata_check(
        l.text, l.phone, l.upi,
        l.rent, l.bhk, l.locality
    ),
    "text": text_check(l.text),
    "text_reuse": text_reuse_check(l.text, lid),
    "price": price_check(l.rent, l.bhk, l.locality),
    "contact": contact_check(l.phone, l.upi, lid),
    "photo": photo_check(l.photos, lid)
}
    w = {
    "metadata": 0.15,
    "text": 0.25,
    "text_reuse": 0.15,
    "price": 0.25,
    "contact": 0.15,
    "photo": 0.05
}
    total = round(sum(checks[k]["score"] * w[k] for k in w))
    label = "green" if total >= 70 else "yellow" if total >= 40 else "red"
    return {"listing_id": lid, "trust_score": total, "label": label, "checks": checks}

def geocode(address):
    return None

def haversine(a, b, c, d):
    R = 6371000
    p1, p2 = math.radians(a), math.radians(c)
    dp, dl = p2 - p1, math.radians(d - b)
    x = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * R * math.asin(math.sqrt(x))

DIRS = {"N": 0, "NE": 45, "E": 90, "SE": 135, "S": 180, "SW": 225, "W": 270, "NW": 315}
def angle_diff(a, b):
    d = abs(a - b) % 360
    return min(d, 360 - d)

def read_code(frame_b64):
    return ""

@app.post("/create-link")
def create_link(r: LinkReq):
    token = secrets.token_urlsafe(8)
    claims = {k: v for k, v in r.claims.items() if v}
    order = list(claims.keys()) or ["main door"]
    random.shuffle(order)
    links[token] = {"created": time.time(), "coords": geocode(r.address) if r.address else None,
                    "claims": claims, "order": order, "code": str(random.randint(1000, 9999)), "result": None}
    return {"token": token, "url": f"{PUBLIC_URL}/verify.html?t={token}"}

@app.get("/link/{token}")
def get_link(token: str):
    L = links.get(token)
    if not L or time.time() - L["created"] > 1800:
        return {"error": "Link expired or invalid"}
    return {"order": L["order"], "code": L["code"]}

@app.post("/verify/{token}")
def verify(token: str, c: Capture):
    L = links.get(token)
    if not L or time.time() - L["created"] > 1800:
        return {"error": "Link expired or invalid"}
    checks = {}
    age = abs(time.time() - c.timestamp / 1000)
    checks["time"] = {"score": 100 if age < 300 else 0, "evidence": [f"Capture was {age:.0f}s from server time"]}
    if L["coords"]:
        d = haversine(c.lat, c.lng, *L["coords"])
        s = 100 if d < 300 else 60 if d < 1000 else 0
        checks["location"] = {"score": s, "evidence": [f"Phone is {d:.0f} m from the listed address"]}
    else:
        checks["location"] = {"score": 50, "evidence": ["Address could not be located, check skipped"]}
    ok, ev = 0, []
    for rd in c.readings:
        claim = L["claims"].get(rd["item"])
        if claim:
            diff = angle_diff(rd["heading"], DIRS[claim])
            good = diff <= 45
            ok += good
            ev.append(f'{rd["item"]}: claimed {claim}, measured {rd["heading"]:.0f} deg ({"match" if good else "mismatch"})')
    n = len(L["claims"]) or 1
    checks["compass"] = {"score": round(100 * ok / n), "evidence": ev or ["No compass claims"]}
    got = read_code(c.frame)
    code_ok = got == L["code"]
    checks["code"] = {"score": 100 if code_ok else 0, "evidence": [f"Expected {L['code']}, read '{got}'"]}
    w = {"location": 0.3, "compass": 0.3, "code": 0.3, "time": 0.1}
    total = round(sum(checks[k]["score"] * w[k] for k in w))
    L["result"] = {"verified": total >= 70 and code_ok, "score": total, "checks": checks}
    return L["result"]

@app.get("/result/{token}")
def result(token: str):
    L = links.get(token)
    return (L or {}).get("result") or {"pending": True}

@app.post("/chat-check")
def chat_check(req: ChatReq):
    t = (req.chat or "").lower()

    hits = [
        k for k in [
            "advance", "abroad", "western union", "token amount",
            "hurry", "urgent", "no visit", "courier", "army",
            "whatsapp only", "many people interested", "pay now",
            "limited time", "send money", "deposit"
        ]
        if k in t
    ]

    if hits:
        return {
            "risk": "high",
            "score": max(0, 100 - len(hits) * 15),
            "evidence": hits,
            "advice": "Do not send money before independently verifying the property and owner."
        }

    return {
        "risk": "low",
        "score": 90,
        "evidence": [],
        "advice": "No major scam-pattern keywords were detected."
    }
@app.post("/action-plan")
def action_plan(req: PlanReq):
    score = req.score

    if score < 40:
        return {
            "priority": "high",
            "actions": [
                "Do not send money or deposits.",
                "Verify the owner independently.",
                "Visit the property before making payment.",
                "Check the phone number and payment details carefully."
            ]
        }

    if score < 70:
        return {
            "priority": "medium",
            "actions": [
                "Verify the property details.",
                "Ask for ownership or rental documents.",
                "Avoid paying before verification."
            ]
        }

    return {
        "priority": "low",
        "actions": [
            "Still verify the owner and property.",
            "Use a proper rental agreement before payment."
        ]
    }
@app.get("/scam-graph")
def scam_graph():
    # Demo seed: intentionally synthetic data for the hackathon graph.
    phones = ["9000000001", "9000000002", "9000000003", "9000000004"]
    listings = [f"demo-listing-{i}" for i in range(1, 9)]
    nodes = [{"id": p, "label": p, "type": "contact"} for p in phones]
    nodes += [{"id": x, "label": x, "type": "listing"} for x in listings]
    edges = []
    for i, lid in enumerate(listings):
        edges.append({"from": lid, "to": phones[i % 4]})
        if i in (2, 5):
            edges.append({"from": lid, "to": phones[(i + 1) % 4]})
    return {"demo": True, "nodes": nodes, "edges": edges}

@app.post("/red-team")
def red_team():
    samples = [
        "Urgent 2 BHK, owner abroad, pay token now, no visit.",
        "2 BHK near metro. Visit available on Saturday. Agreement before payment.",
        "Army owner transferred, courier keys after advance.",
        "Bright 1 BHK. WhatsApp only. Many people interested. Pay today.",
        "Family flat, normal rent, viewing available, no advance before agreement.",
        "Owner abroad, Western Union deposit required before showing address.",
        "Studio apartment, schedule a visit and verify documents first.",
        "Hurry! Token amount required in 10 minutes to reserve this flat.",
        "2 BHK with normal rent. Video call and physical visit available.",
        "No property visit. Send UPI advance and I will courier the keys."
    ]
    results = []
    for s in samples:
        r = text_check(s)
        results.append({"listing": s, "trust_score": r["score"], "caught_as_risky": r["score"] < 50})
    return {"samples": results, "caught": sum(x["caught_as_risky"] for x in results), "total": len(results)}

app.mount("/", StaticFiles(directory="../frontend", html=True), name="frontend")