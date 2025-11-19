"""
Database Schemas for Invoice & Payment Automation Tool

Each Pydantic model corresponds to a MongoDB collection (lowercased class name).
"""
from typing import List, Optional, Literal
from pydantic import BaseModel, Field, EmailStr
from datetime import date, datetime

# Auth and org
class User(BaseModel):
    email: EmailStr
    name: str
    password_hash: str
    role: Literal["Admin", "Accountant", "Viewer"] = "Admin"

class Session(BaseModel):
    user_id: str
    token: str
    expires_at: datetime

# Business data
class Client(BaseModel):
    name: str
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    company: Optional[str] = None
    address: Optional[str] = None
    notes: Optional[str] = None

class InvoiceItem(BaseModel):
    description: str
    quantity: float = Field(1, ge=0)
    unit_price: float = Field(0, ge=0)
    tax_rate: float = Field(0, ge=0, description="Tax rate as percentage e.g. 16 for 16%")

class Invoice(BaseModel):
    client_id: str
    invoice_number: str
    issue_date: date
    due_date: date
    currency: str = "KES"
    items: List[InvoiceItem]
    notes: Optional[str] = None
    status: Literal["Pending", "Paid", "Overdue"] = "Pending"
    subtotal: float
    tax_total: float
    total: float

class Payment(BaseModel):
    invoice_id: str
    amount: float
    method: Literal["M-Pesa", "Manual", "Bank"] = "M-Pesa"
    reference: Optional[str] = None
    status: Literal["Success", "Failed", "Pending"] = "Pending"
    raw: Optional[dict] = None

class MpesaConfig(BaseModel):
    consumer_key: str
    consumer_secret: str
    shortcode: str = Field(..., description="Business shortcode")
    passkey: str = Field(..., description="Lipa na M-PESA Online Passkey")
    callback_url: str
    environment: Literal["sandbox", "production"] = "sandbox"
