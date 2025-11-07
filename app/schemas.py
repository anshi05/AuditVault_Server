# app/schemas.py
from pydantic import BaseModel
from typing import Optional

class UploadResponse(BaseModel):
    ipfs_cid: str
    content_hash: str

class SignPayload(BaseModel):
    contract_address: str
    chain_id: int
    content_hash: str
    summary_hash: Optional[str]
    inspector: str
    inspector_timestamp: int
    nonce: str

class SubmitInspectionIn(BaseModel):
    content_hash: str
    summary_hash: Optional[str]
    inspector: str
    inspector_timestamp: int
    nonce: str
    signature: str
    meta: Optional[bytes] = None

class IssueCertificateIn(BaseModel):
    cert_id: str
    owner: str
    expiry: Optional[int]
