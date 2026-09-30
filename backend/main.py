
import os, json, time, math, random, secrets, re, sqlite3, hashlib
import requests, anthropic
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()
client = anthropic.Anthropic()
MODEL = "claude-haiku-4-5-20251001"
PUBLIC_URL = os.getenv("PUBLIC_URL", "http://localhost:8000")

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

db = sqlite3.connect("trust.db", check_same_thread=False)
db.execute("create table if not exists contacts(k text, lid text)")
db.execute("create table if not exists photo_hashes(h text, lid text)")
db.commit()
links = {}

class Listing(BaseModel):
    text: str
    phone: str = ""
    upi: str = ""
    rent: float = 0
    bhk: int = 1
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

def claude_json(prompt, max_tokens=500):
    r = client.messages.create(
        model=MODEL, max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}]
    )
    raw = r.content[0].text
    m = re.search(r"\{.*\}", raw, re.S)
    return json.loads(m.group()) if m else {}

def text_check(text):
    kws = ["advance", "abroad", "western union", "token amount", "hurry", "urgent",
           "no visit", "courier", "army", "whatsapp only", "many people interested"]
    hits = [k for k in kws if k in text.lower()]
    try:
        d = claude_json(
            "You detect rental scams in India. Return ONLY JSON like "
            '{"scam_probability": 0-100, "reasons": ["short reason"]}\nListing:\n' + text,
            400
        )
        p, reasons, conf = d["scam_probability"], d["reasons"], 0.8
    except Exception:
        p, reasons, conf = min(100, len(hits) * 25), [f"Scam keyword: {h}" for h in hits], 0.4
    return {"score": 100 - p, "confidence": conf, "evidence": reasons or ["No scam patterns found"]}

AVG_RENT = {1: 12000, 2: 20000, 3: 30000}
def price_check(rent, bhk):
    avg = AVG_RENT.get(bhk, 20000)
    if rent <= 0:
        return {"score": 50, "confidence": 0.2, "evidence": ["Rent not given"]}
    if rent < 0.5 * avg:
        return {"score": 15, "confidence": 0.7, "evidence": [f"Rent {rent:.0f} is far below the typical {avg} for {bhk} BHK"]}
    if rent < 0.7 * avg:
        return {"score": 50, "confidence": 0.6, "evidence": ["Rent is noticeably below the area average"]}
    return {"score": 90, "confidence": 0.6, "evidence": ["Rent looks normal for the area"]}

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
    # Optional vision plausibility check; if API is unavailable, the hash check still works.
    try:
        raw = photos[0].split(",", 1)[1] if "," in photos[0] else photos[0]
        r = client.messages.create(model=MODEL, max_tokens=180, messages=[{"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": raw}},
            {"type": "text", "text": "For a rental listing photo, return JSON only: {\"plausible\": true/false, \"reason\": \"short\"}. Do not identify people."}
        ]}])
        d = json.loads(re.search(r"\{.*\}", r.content[0].text, re.S).group())
        ev.append("Vision check: " + d.get("reason", "image reviewed"))
        if d.get("plausible") is False:
            score = min(score, 45)
    except Exception:
        pass
    return {"score": score, "confidence": 0.65, "evidence": ev}

@app.post("/analyze")
def analyze(l: Listing):
    lid = hashlib.md5(l.text.encode()).hexdigest()[:10]
    checks = {
        "text": text_check(l.text),
        "price": price_check(l.rent, l.bhk),
        "contact": contact_check(l.phone, l.upi, lid),
        "photo": photo_check(l.photos, lid)
    }
    w = {"text": 0.35, "price": 0.20, "contact": 0.30, "photo": 0.15}
    total = round(sum(checks[k]["score"] * w[k] for k in w))
    label = "green" if total >= 70 else "yellow" if total >= 40 else "red"
    return {"listing_id": lid, "trust_score": total, "label": label, "checks": checks}

def geocode(address):
    try:
        r = requests.get("https://nominatim.openstreetmap.org/search",
                         params={"q": address, "format": "json", "limit": 1},
                         headers={"User-Agent": "trustlens-hackathon"}, timeout=8).json()
        return (float(r[0]["lat"]), float(r[0]["lon"])) if r else None
    except Exception:
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
    try:
        r = client.messages.create(model=MODEL, max_tokens=20, messages=[{"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": frame_b64}},
            {"type": "text", "text": "Read the handwritten number on the paper in this image. Reply with digits only, or NONE."}]}])
        return re.sub(r"\D", "", r.content[0].text)
    except Exception:
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
def chat_check(r: ChatReq):
    try:
        d = claude_json(
            'Analyze this rental-related chat for scam warning signs. Return ONLY JSON: '
            '{"score":0-100,"flags":["short flag"],"safe_signs":["short sign"]}. '
            'Score means trust, where 100 is safer. Focus on advance-payment pressure, refusing visits/video calls, '
            'identity/payment inconsistencies, urgency, and suspicious links.\nCHAT:\n' + r.chat, 500)
        return d
    except Exception:
        low = r.chat.lower()
        flags = []
        for term in ["advance", "urgent", "whatsapp only", "no visit", "token", "pay now"]:
            if term in low:
                flags.append("Chat contains: " + term)
        return {"score": max(0, 100 - 15 * len(flags)), "flags": flags, "safe_signs": []}

@app.post("/action-plan")
def action_plan(r: ChatReq):
    try:
        d = claude_json(
            'For this rental conversation, return ONLY JSON with keys '
            '"questions_before_paying" (array), "safe_payment_tips" (array), "complaint_draft" (string). '
            'Keep advice practical and concise. Do not claim a scam is proven.\nCHAT:\n' + r.chat, 600)
        return d
    except Exception:
        return {
            "questions_before_paying": [
                "Can I visit the property before paying?",
                "Can you provide an ID/name matching the agreement?",
                "Can we use a documented rental agreement before payment?"
            ],
            "safe_payment_tips": [
                "Do not pay an advance just because of urgency.",
                "Verify the property and recipient before transferring money."
            ],
            "complaint_draft": "I want to report a suspected rental scam. Please review the attached conversation and payment details."
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
