# app/models.py
from typing import Optional
from sqlmodel import SQLModel, Field
from datetime import datetime

class Inspection(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    content_hash: str
    summary_hash: str | None
    ipfs_cid: str | None
    inspector: str
    submitter: str
    inspector_timestamp: int
    nonce: str
    signature: str
    onchain_tx: str | None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Certificate(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    cert_hash: str
    issuer: str
    owner: str
    expiry: Optional[int] = None
    revoked: bool = False
    issued_at: int
    tx_hash: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class AgentAction(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    action_hash: str
    agent: str
    action_type: str
    meta: str | None
    tx_hash: str | None
    created_at: datetime = Field(default_factory=datetime.utcnow)
