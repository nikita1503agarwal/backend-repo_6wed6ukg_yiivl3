import os
import hashlib
import uuid
from datetime import datetime, timedelta, timezone, date
from typing import List, Optional, Literal, Dict, Any

import requests
from fastapi import FastAPI, Depends, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Client as ClientSchema, Invoice as InvoiceSchema, InvoiceItem as InvoiceItemSchema, Payment as PaymentSchema, MpesaConfig as MpesaConfigSchema, Session as SessionSchema


app = FastAPI(title="Invoice & Payment Automation API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -------------------- Utilities --------------------

def oid(obj_id: str) -> ObjectId:
    try:
        return ObjectId(obj_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")


def serialize_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return doc
    out = {}
    for k, v in doc.items():
        if k == "_id":
            out["id"] = str(v)
        elif isinstance(v, ObjectId):
            out[k] = str(v)
        elif isinstance(v, datetime):
            out[k] = v.isoformat()
        else:
            out[k] = v
    return out


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def create_session(user_id: str) -> str:
    token = uuid.uuid4().hex
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
    create_document("session", SessionSchema(user_id=user_id, token=token, expires_at=expires_at))
    return token


def get_user_from_token(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = authorization.split(" ")[-1].strip()
    sess = db["session"].find_one({"token": token})
    if not sess:
        raise HTTPException(status_code=401, detail="Invalid session")
    if sess.get("expires_at") and sess["expires_at"] < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Session expired")
    user = db["user"].find_one({"_id": sess["user_id"] if isinstance(sess["user_id"], ObjectId) else ObjectId(sess["user_id"])})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return serialize_doc(user)


# -------------------- Models (request/response) --------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    name: str
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class AuthResponse(BaseModel):
    token: str
    user: Dict[str, Any]

class ClientCreateRequest(ClientSchema):
    pass

class InvoiceCreateRequest(BaseModel):
    client_id: str
    issue_date: date
    due_date: date
    currency: str = "KES"
    items: List[InvoiceItemSchema]
    notes: Optional[str] = None

class MpesaConfigRequest(MpesaConfigSchema):
    pass

class STKPushRequest(BaseModel):
    invoice_id: str
    phone: str


# -------------------- Health/Test --------------------

@app.get("/")
def read_root():
    return {"message": "Invoice & Payment Automation API running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()
    except Exception as e:
        response["database"] = f"⚠️ {str(e)[:80]}"
    return response


# -------------------- Auth --------------------

@app.post("/auth/register", response_model=AuthResponse)
def register(payload: RegisterRequest):
    existing = db["user"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = UserSchema(email=payload.email, name=payload.name, password_hash=hash_password(payload.password), role="Admin")
    user_id = create_document("user", user)
    token = create_session(user_id)
    udoc = db["user"].find_one({"_id": ObjectId(user_id)})
    return AuthResponse(token=token, user=serialize_doc(udoc))

@app.post("/auth/login", response_model=AuthResponse)
def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email})
    if not user or user.get("password_hash") != hash_password(payload.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_session(str(user["_id"]))
    return AuthResponse(token=token, user=serialize_doc(user))

@app.get("/me")
def me(current=Depends(get_user_from_token)):
    return current


# -------------------- Clients --------------------

@app.post("/clients")
def create_client(payload: ClientCreateRequest, current=Depends(get_user_from_token)):
    client_id = create_document("client", payload)
    doc = db["client"].find_one({"_id": ObjectId(client_id)})
    return serialize_doc(doc)

@app.get("/clients")
def list_clients(current=Depends(get_user_from_token)):
    docs = get_documents("client")
    return [serialize_doc(d) for d in docs]

@app.get("/clients/{client_id}")
def get_client(client_id: str, current=Depends(get_user_from_token)):
    doc = db["client"].find_one({"_id": oid(client_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Client not found")
    # aggregate balances
    invoices = list(db["invoice"].find({"client_id": client_id}))
    total = sum(i.get("total", 0) for i in invoices)
    paid = sum(p.get("amount", 0) for p in db["payment"].find({"invoice_id": {"$in": [str(i["_id"]) for i in invoices]}, "status": "Success"}))
    balance = total - paid
    out = serialize_doc(doc)
    out["stats"] = {"total_invoiced": total, "total_paid": paid, "outstanding": balance}
    out["invoices"] = [serialize_doc(i) for i in invoices]
    return out

@app.put("/clients/{client_id}")
def update_client(client_id: str, payload: ClientCreateRequest, current=Depends(get_user_from_token)):
    res = db["client"].update_one({"_id": oid(client_id)}, {"$set": payload.model_dump()})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Client not found")
    doc = db["client"].find_one({"_id": oid(client_id)})
    return serialize_doc(doc)

@app.delete("/clients/{client_id}")
def delete_client(client_id: str, current=Depends(get_user_from_token)):
    db["client"].delete_one({"_id": oid(client_id)})
    return {"success": True}


# -------------------- Invoices --------------------

def compute_totals(items: List[Dict[str, Any]]):
    subtotal = sum(float(i.get("quantity", 0)) * float(i.get("unit_price", 0)) for i in items)
    tax_total = sum((float(i.get("quantity", 0)) * float(i.get("unit_price", 0))) * (float(i.get("tax_rate", 0)) / 100.0) for i in items)
    total = subtotal + tax_total
    return subtotal, tax_total, total


def next_invoice_number() -> str:
    last = db["invoice"].find().sort([("created_at", -1)]).limit(1)
    try:
        last_doc = list(last)[0]
        prev = last_doc.get("invoice_number", "INV-0000")
        n = int(prev.split("-")[-1]) + 1
    except Exception:
        n = 1
    return f"INV-{n:04d}"

@app.post("/invoices")
def create_invoice(payload: InvoiceCreateRequest, current=Depends(get_user_from_token)):
    if not db["client"].find_one({"_id": oid(payload.client_id)}):
        raise HTTPException(status_code=400, detail="Client does not exist")
    subtotal, tax_total, total = compute_totals([i.model_dump() for i in payload.items])
    invoice = InvoiceSchema(
        client_id=payload.client_id,
        invoice_number=next_invoice_number(),
        issue_date=payload.issue_date,
        due_date=payload.due_date,
        currency=payload.currency,
        items=payload.items,
        notes=payload.notes,
        status="Pending",
        subtotal=subtotal,
        tax_total=tax_total,
        total=total,
    )
    inv_id = create_document("invoice", invoice)
    doc = db["invoice"].find_one({"_id": ObjectId(inv_id)})
    return serialize_doc(doc)

@app.get("/invoices")
def list_invoices(status: Optional[str] = None, current=Depends(get_user_from_token)):
    q: Dict[str, Any] = {}
    if status:
        q["status"] = status
    docs = list(db["invoice"].find(q).sort([("created_at", -1)]))
    return [serialize_doc(d) for d in docs]

@app.get("/invoices/{invoice_id}")
def get_invoice(invoice_id: str, current=Depends(get_user_from_token)):
    doc = db["invoice"].find_one({"_id": oid(invoice_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Invoice not found")
    client = db["client"].find_one({"_id": oid(doc["client_id"])}) if ObjectId.is_valid(doc.get("client_id", "")) else db["client"].find_one({"_id": oid(str(doc["client_id"]))}) if doc.get("client_id") else None
    out = serialize_doc(doc)
    out["client"] = serialize_doc(client) if client else None
    payments = list(db["payment"].find({"invoice_id": str(doc["_id"]), "status": "Success"}))
    out["payments"] = [serialize_doc(p) for p in payments]
    return out

@app.put("/invoices/{invoice_id}")
def update_invoice(invoice_id: str, payload: InvoiceCreateRequest, current=Depends(get_user_from_token)):
    subtotal, tax_total, total = compute_totals([i.model_dump() for i in payload.items])
    update = payload.model_dump()
    update.update({"subtotal": subtotal, "tax_total": tax_total, "total": total})
    res = db["invoice"].update_one({"_id": oid(invoice_id)}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Invoice not found")
    doc = db["invoice"].find_one({"_id": oid(invoice_id)})
    return serialize_doc(doc)

@app.post("/invoices/{invoice_id}/status")
def set_invoice_status(invoice_id: str, status: Literal["Pending", "Paid", "Overdue"], current=Depends(get_user_from_token)):
    db["invoice"].update_one({"_id": oid(invoice_id)}, {"$set": {"status": status}})
    return {"success": True}

@app.get("/invoices/{invoice_id}/html")
def invoice_html(invoice_id: str, current=Depends(get_user_from_token)):
    inv = db["invoice"].find_one({"_id": oid(invoice_id)})
    if not inv:
        raise HTTPException(status_code=404, detail="Invoice not found")
    client = db["client"].find_one({"_id": oid(inv["client_id"])}) if ObjectId.is_valid(inv.get("client_id", "")) else None
    inv_s = serialize_doc(inv)
    cli_s = serialize_doc(client) if client else {}
    # very simple HTML for preview/print to PDF on client side
    rows = "".join([
        f"<tr><td>{i['description']}</td><td style='text-align:right'>{i['quantity']}</td><td style='text-align:right'>{i['unit_price']:.2f}</td><td style='text-align:right'>{i['tax_rate']}%</td><td style='text-align:right'>{(i['quantity']*i['unit_price']):.2f}</td></tr>"
        for i in inv_s.get("items", [])
    ])
    html = f"""
    <html><head><meta charset='utf-8'><title>{inv_s['invoice_number']}</title>
    <style>body{{font-family:Arial;padding:24px;color:#0f172a}} table{{width:100%;border-collapse:collapse}} td,th{{border-bottom:1px solid #e2e8f0;padding:8px}}</style>
    </head><body>
    <h1>Invoice {inv_s['invoice_number']}</h1>
    <p><strong>Client:</strong> {cli_s.get('name','')}</p>
    <p><strong>Issue:</strong> {inv_s.get('issue_date','')} • <strong>Due:</strong> {inv_s.get('due_date','')}</p>
    <table><thead><tr><th>Description</th><th>Qty</th><th>Unit</th><th>Tax</th><th>Amount</th></tr></thead><tbody>{rows}</tbody></table>
    <h3 style='text-align:right'>Subtotal: {inv_s.get('subtotal',0):.2f} {inv_s.get('currency','')}</h3>
    <h3 style='text-align:right'>Tax: {inv_s.get('tax_total',0):.2f} {inv_s.get('currency','')}</h3>
    <h2 style='text-align:right'>Total: {inv_s.get('total',0):.2f} {inv_s.get('currency','')}</h2>
    <p>{inv_s.get('notes','')}</p>
    </body></html>
    """
    return html


# -------------------- M-Pesa Integration --------------------

def get_user_mpesa_config(user_id: str) -> Optional[Dict[str, Any]]:
    return db["mpesaconfig"].find_one({"user_id": user_id})

@app.post("/mpesa/config")
def set_mpesa_config(payload: MpesaConfigRequest, current=Depends(get_user_from_token)):
    existing = get_user_mpesa_config(current["id"])
    doc = payload.model_dump()
    doc.update({"user_id": current["id"]})
    if existing:
        db["mpesaconfig"].update_one({"_id": existing["_id"]}, {"$set": doc})
    else:
        create_document("mpesaconfig", doc)
    return {"success": True}

@app.get("/mpesa/config")
def get_mpesa_config(current=Depends(get_user_from_token)):
    cfg = get_user_mpesa_config(current["id"]) or {}
    if cfg:
        cfg = serialize_doc(cfg)
        # Do not expose secrets
        for k in ["consumer_key", "consumer_secret", "passkey"]:
            if k in cfg:
                cfg[k] = "***"
    return cfg


def daraja_base(env: str) -> str:
    return "https://sandbox.safaricom.co.ke" if env == "sandbox" else "https://api.safaricom.co.ke"


def daraja_access_token(cfg: Dict[str, Any]) -> str:
    url = f"{daraja_base(cfg['environment'])}/oauth/v1/generate?grant_type=client_credentials"
    r = requests.get(url, auth=(cfg["consumer_key"], cfg["consumer_secret"]))
    if r.status_code != 200:
        raise HTTPException(status_code=400, detail=f"M-Pesa auth failed: {r.text}")
    return r.json().get("access_token")

@app.post("/payments/stkpush")
def initiate_stk_push(payload: STKPushRequest, current=Depends(get_user_from_token)):
    inv = db["invoice"].find_one({"_id": oid(payload.invoice_id)})
    if not inv:
        raise HTTPException(status_code=404, detail="Invoice not found")
    cfg = get_user_mpesa_config(current["id"])
    if not cfg:
        raise HTTPException(status_code=400, detail="M-Pesa not configured")
    cfg = serialize_doc(cfg)

    token = daraja_access_token(cfg)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    # Password = Base64.encode(shortcode + passkey + timestamp)
    import base64
    password = base64.b64encode((cfg["shortcode"] + cfg["passkey"] + timestamp).encode()).decode()

    stk_url = f"{daraja_base(cfg['environment'])}/mpesa/stkpush/v1/processrequest"
    callback_url = cfg["callback_url"]
    payload_mpesa = {
        "BusinessShortCode": cfg["shortcode"],
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": int(round(inv.get("total", 0))),
        "PartyA": payload.phone,
        "PartyB": cfg["shortcode"],
        "PhoneNumber": payload.phone,
        "CallBackURL": callback_url,
        "AccountReference": inv.get("invoice_number", "INV"),
        "TransactionDesc": f"Payment for {inv.get('invoice_number')}"
    }
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    r = requests.post(stk_url, json=payload_mpesa, headers=headers)
    resp = r.json() if r.headers.get("content-type", "").startswith("application/json") else {"raw": r.text}

    # Record a pending payment attempt
    pay = PaymentSchema(
        invoice_id=str(inv["_id"]),
        amount=float(inv.get("total", 0)),
        method="M-Pesa",
        reference=resp.get("CheckoutRequestID") or resp.get("MerchantRequestID"),
        status="Pending",
        raw=resp,
    )
    pay_id = create_document("payment", pay)

    return {"attempt": serialize_doc(db["payment"].find_one({"_id": ObjectId(pay_id)})), "mpesa_response": resp}

@app.post("/mpesa/callback")
async def mpesa_callback(request: Request):
    body = await request.json()
    # Extract results
    result_code = body.get("Body", {}).get("stkCallback", {}).get("ResultCode")
    result_desc = body.get("Body", {}).get("stkCallback", {}).get("ResultDesc")
    checkout_id = body.get("Body", {}).get("stkCallback", {}).get("CheckoutRequestID")
    items = body.get("Body", {}).get("stkCallback", {}).get("CallbackMetadata", {}).get("Item", [])

    # Update payment by reference
    pay = db["payment"].find_one({"reference": checkout_id})
    if pay:
        status = "Success" if result_code == 0 else "Failed"
        db["payment"].update_one({"_id": pay["_id"]}, {"$set": {"status": status, "raw": body, "updated_at": datetime.now(timezone.utc)}})
        if status == "Success":
            # mark invoice paid
            db["invoice"].update_one({"_id": ObjectId(pay["invoice_id"])}, {"$set": {"status": "Paid", "updated_at": datetime.now(timezone.utc)}})
    return {"result": result_desc, "ok": True}


# -------------------- Dashboard --------------------

@app.get("/dashboard/summary")
def dashboard_summary(current=Depends(get_user_from_token)):
    total = db["invoice"].aggregate([
        {"$group": {"_id": "$status", "sum": {"$sum": "$total"}, "count": {"$sum": 1}}}
    ])
    by_status = {d["_id"]: {"amount": d["sum"], "count": d["count"]} for d in total}

    # Monthly cash flow (sum of successful payments by month)
    pipeline = [
        {"$match": {"status": "Success"}},
        {"$group": {"_id": {"y": {"$year": "$created_at"}, "m": {"$month": "$created_at"}}, "amount": {"$sum": "$amount"}}},
        {"$sort": {"_id.y": 1, "_id.m": 1}}
    ]
    monthly = list(db["payment"].aggregate(pipeline))
    monthly_series = [
        {"label": f"{m['_id']['y']}-{m['_id']['m']:02d}", "amount": m["amount"]}
        for m in monthly
    ]

    recent = [serialize_doc(p) for p in db["payment"].find().sort([("created_at", -1)]).limit(10)]

    return {
        "status": {
            "Paid": by_status.get("Paid", {}).get("amount", 0),
            "Pending": by_status.get("Pending", {}).get("amount", 0),
            "Overdue": by_status.get("Overdue", {}).get("amount", 0),
        },
        "counts": {
            "Paid": by_status.get("Paid", {}).get("count", 0),
            "Pending": by_status.get("Pending", {}).get("count", 0),
            "Overdue": by_status.get("Overdue", {}).get("count", 0),
        },
        "monthly": monthly_series,
        "recent": recent,
    }
