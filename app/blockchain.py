# app/blockchain.py
import json, os
from web3 import Web3
from eth_account.messages import encode_defunct
from app.settings import settings
from hexbytes import HexBytes

# load ABI
import json, os

# Use current working directory as base
ROOT_DIR = os.getcwd()
ABI_PATH = os.path.join(ROOT_DIR, "artifacts", "Compliance.json")

with open(ABI_PATH, "r") as f:
    artifact = json.load(f)

ABI = artifact.get("abi", artifact)

w3 = Web3(Web3.HTTPProvider(settings.RPC_URL))
contract = w3.eth.contract(address=Web3.to_checksum_address(settings.CONTRACT_ADDRESS), abi=ABI)

def get_chain_id():
    return int(settings.CHAIN_ID)

def _maybe_bytes32(value):
    """
    Accepts bytes, HexBytes, or hex string '0x...' and returns raw bytes (32 bytes).
    If given None or empty-like, returns 32 zero bytes.
    """
    if value is None:
        return b"\x00" * 32
    if isinstance(value, (bytes, bytearray, HexBytes)):
        # If it's bytes but not 32 long, left-pad with zeros to 32
        b = bytes(value)
        return b.rjust(32, b"\x00") if len(b) < 32 else b[:32]
    if isinstance(value, str):
        s = value
        if s.startswith("0x"):
            s = s[2:]
        # allow short hex (e.g., hashed text) — pad/truncate to 32 bytes
        b = bytes.fromhex(s)
        return b.rjust(32, b"\x00") if len(b) < 32 else b[:32]
    raise TypeError("Unsupported type for bytes32 conversion")

def build_inspection_raw_hash(contract_address, chain_id, content_hash, summary_hash, inspector, inspector_timestamp, nonce):
    """
    Build the Solidity-style keccak256 hash of:
      keccak256(address(contract), uint256(chainId), bytes32(contentHash),
                bytes32(summaryHash), address(inspector), uint256(inspectorTimestamp), bytes32(nonce))
    Returns raw bytes (32 bytes).
    """
    # prepare types and values
    types = ["address", "uint256", "bytes32", "bytes32", "address", "uint256", "bytes32"]

    addr = Web3.to_checksum_address(contract_address)
    inspector_addr = Web3.to_checksum_address(inspector)
    chain_id_int = int(chain_id)

    content_b = _maybe_bytes32(content_hash)
    summary_b = _maybe_bytes32(summary_hash)
    nonce_b = _maybe_bytes32(nonce)

    values = [
        addr,
        chain_id_int,
        content_b,
        summary_b,
        inspector_addr,
        int(inspector_timestamp),
        nonce_b
    ]

    # Note: web3.py function name is solidity_keccak (underscore)
    raw = Web3.solidity_keccak(types, values)  # returns bytes
    return raw

def recover_signer_from_raw(raw_hash: bytes, signature: str) -> str:
    """
    Recover the address that signed raw_hash using Ethereum personal_sign semantics
    (i.e. signMessage(arrayify(rawHash)) from ethers).
    """
    # raw_hash must be bytes
    if isinstance(raw_hash, str):
        # allow hexstring
        raw_hash = HexBytes(raw_hash)

    msg = encode_defunct(primitive=raw_hash)  # use eth-account to create signable message
    signer = w3.eth.account.recover_message(msg, signature=signature)
    return Web3.to_checksum_address(signer)

def _send_signed_transaction_and_wait(signed_tx):
    """
    Helper that works with both eth-account/web3 return shapes:
      - signed_tx.rawTransaction  (older)
      - signed_tx.raw_transaction (newer)
    Returns the transaction receipt.
    """
    raw = None
    # try both attribute names
    if hasattr(signed_tx, "rawTransaction"):
        raw = signed_tx.rawTransaction
    elif hasattr(signed_tx, "raw_transaction"):
        raw = signed_tx.raw_transaction
    else:
        # last-resort: look through dict representation
        try:
            raw = signed_tx._dict.get("rawTransaction") or signed_tx.dict_.get("raw_transaction")
        except Exception:
            raw = None

    if raw is None:
        raise RuntimeError("Signed transaction object does not contain raw tx bytes (rawTransaction/raw_transaction)")

    tx_hash = w3.eth.send_raw_transaction(raw)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt


def record_inspection_with_signature(
    submitter_private_key,
    content_hash,
    summary_hash,
    inspector,
    inspector_timestamp,
    nonce,
    signature,
    meta=b"",
):
    acct = w3.eth.account.from_key(submitter_private_key)

    tx = contract.functions.recordInspectionWithSignature(
        HexBytes(content_hash),
        HexBytes(summary_hash or b"\x00"*32),
        Web3.to_checksum_address(inspector),
        int(inspector_timestamp),
        HexBytes(nonce),
        HexBytes(signature),
        meta,
    ).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 800000,
        "gasPrice": w3.eth.gas_price,
    })

    # Sign the tx
    signed = w3.eth.account.sign_transaction(tx, private_key=submitter_private_key)
    # Use helper to extract raw bytes and send
    receipt = _send_signed_transaction_and_wait(signed)
    return receipt


def issue_certificate(submitter_private_key, cert_hash, owner, expiry):
    acct = w3.eth.account.from_key(submitter_private_key)

    tx = contract.functions.issueCertificate(
        HexBytes(cert_hash),
        Web3.to_checksum_address(owner),
        int(expiry),
    ).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 400000,
        "gasPrice": w3.eth.gas_price,
    })

    signed = w3.eth.account.sign_transaction(tx, private_key=submitter_private_key)
    receipt = _send_signed_transaction_and_wait(signed)
    return receipt


def revoke_certificate(submitter_private_key, cert_hash):
    acct = w3.eth.account.from_key(submitter_private_key)

    tx = contract.functions.revokeCertificate(HexBytes(cert_hash)).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 200000,
        "gasPrice": w3.eth.gas_price,
    })

    signed = w3.eth.account.sign_transaction(tx, private_key=submitter_private_key)
    receipt = _send_signed_transaction_and_wait(signed)
    return receipt


def _role_bytes32(role_name: str) -> bytes:
    # Accept either role name like "INSPECTOR_ROLE" or a bytes32 hex string
    if role_name.startswith("0x") and len(role_name) == 66:
        return HexBytes(role_name)
    return Web3.keccak(text=role_name)  # returns bytes

def grant_role(admin_private_key: str, role_name: str, target_address: str):
    acct = w3.eth.account.from_key(admin_private_key)
    role_b = _role_bytes32(role_name)
    tx = contract.functions.grantRole(role_b, Web3.to_checksum_address(target_address)).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 200000
    })
    signed = w3.eth.account.sign_transaction(tx, private_key=admin_private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash)

def revoke_role(admin_private_key: str, role_name: str, target_address: str):
    acct = w3.eth.account.from_key(admin_private_key)
    role_b = _role_bytes32(role_name)
    tx = contract.functions.revokeRole(role_b, Web3.to_checksum_address(target_address)).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 200000
    })
    signed = w3.eth.account.sign_transaction(tx, private_key=admin_private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash)

def has_role(role_name: str, address: str) -> bool:
    role_b = _role_bytes32(role_name)
    return contract.functions.hasRole(role_b, Web3.to_checksum_address(address)).call()

def check_inspection_onchain(content_hash_hex: str) -> bool:
    # contract has mapping seenInspections(bytes32) -> bool
    h = content_hash_hex if content_hash_hex.startswith("0x") else "0x" + content_hash_hex
    return contract.functions.seenInspections(HexBytes(h)).call()

def is_certificate_valid(cert_hash_hex: str) -> bool:
    h = cert_hash_hex if cert_hash_hex.startswith("0x") else "0x" + cert_hash_hex
    return contract.functions.isCertificateValid(HexBytes(h)).call()# app/blockchain.py
import json, os
from web3 import Web3
from eth_account.messages import encode_defunct
from app.settings import settings
from hexbytes import HexBytes

w3 = Web3(Web3.HTTPProvider(settings.RPC_URL))
contract = w3.eth.contract(address=Web3.to_checksum_address(settings.CONTRACT_ADDRESS), abi=ABI)

def get_chain_id():
    return int(settings.CHAIN_ID)

def _maybe_bytes32(value):
    """
    Accepts bytes, HexBytes, or hex string '0x...' and returns raw bytes (32 bytes).
    If given None or empty-like, returns 32 zero bytes.
    """
    if value is None:
        return b"\x00" * 32
    if isinstance(value, (bytes, bytearray, HexBytes)):
        # If it's bytes but not 32 long, left-pad with zeros to 32
        b = bytes(value)
        return b.rjust(32, b"\x00") if len(b) < 32 else b[:32]
    if isinstance(value, str):
        s = value
        if s.startswith("0x"):
            s = s[2:]
        # allow short hex (e.g., hashed text) — pad/truncate to 32 bytes
        b = bytes.fromhex(s)
        return b.rjust(32, b"\x00") if len(b) < 32 else b[:32]
    raise TypeError("Unsupported type for bytes32 conversion")

def build_inspection_raw_hash(contract_address, chain_id, content_hash, summary_hash, inspector, inspector_timestamp, nonce):
    """
    Build the Solidity-style keccak256 hash of:
      keccak256(address(contract), uint256(chainId), bytes32(contentHash),
                bytes32(summaryHash), address(inspector), uint256(inspectorTimestamp), bytes32(nonce))
    Returns raw bytes (32 bytes).
    """
    # prepare types and values
    types = ["address", "uint256", "bytes32", "bytes32", "address", "uint256", "bytes32"]

    addr = Web3.to_checksum_address(contract_address)
    inspector_addr = Web3.to_checksum_address(inspector)
    chain_id_int = int(chain_id)

    content_b = _maybe_bytes32(content_hash)
    summary_b = _maybe_bytes32(summary_hash)
    nonce_b = _maybe_bytes32(nonce)

    values = [
        addr,
        chain_id_int,
        content_b,
        summary_b,
        inspector_addr,
        int(inspector_timestamp),
        nonce_b
    ]

    # Note: web3.py function name is solidity_keccak (underscore)
    raw = Web3.solidity_keccak(types, values)  # returns bytes
    return raw

def recover_signer_from_raw(raw_hash: bytes, signature: str) -> str:
    """
    Recover the address that signed raw_hash using Ethereum personal_sign semantics
    (i.e. signMessage(arrayify(rawHash)) from ethers).
    """
    # raw_hash must be bytes
    if isinstance(raw_hash, str):
        # allow hexstring
        raw_hash = HexBytes(raw_hash)

    msg = encode_defunct(primitive=raw_hash)  # use eth-account to create signable message
    signer = w3.eth.account.recover_message(msg, signature=signature)
    return Web3.to_checksum_address(signer)

def _send_signed_transaction_and_wait(signed_tx):
    """
    Helper that works with both eth-account/web3 return shapes:
      - signed_tx.rawTransaction  (older)
      - signed_tx.raw_transaction (newer)
    Returns the transaction receipt.
    """
    raw = None
    # try both attribute names
    if hasattr(signed_tx, "rawTransaction"):
        raw = signed_tx.rawTransaction
    elif hasattr(signed_tx, "raw_transaction"):
        raw = signed_tx.raw_transaction
    else:
        # last-resort: look through dict representation
        try:
            raw = signed_tx._dict.get("rawTransaction") or signed_tx.dict_.get("raw_transaction")
        except Exception:
            raw = None

    if raw is None:
        raise RuntimeError("Signed transaction object does not contain raw tx bytes (rawTransaction/raw_transaction)")

    tx_hash = w3.eth.send_raw_transaction(raw)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt


def record_inspection_with_signature(
    submitter_private_key,
    content_hash,
    summary_hash,
    inspector,
    inspector_timestamp,
    nonce,
    signature,
    meta=b"",
):
    acct = w3.eth.account.from_key(submitter_private_key)

    tx = contract.functions.recordInspectionWithSignature(
        HexBytes(content_hash),
        HexBytes(summary_hash or b"\x00"*32),
        Web3.to_checksum_address(inspector),
        int(inspector_timestamp),
        HexBytes(nonce),
        HexBytes(signature),
        meta,
    ).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 800000,
        "gasPrice": w3.eth.gas_price,
    })

    # Sign the tx
    signed = w3.eth.account.sign_transaction(tx, private_key=submitter_private_key)
    # Use helper to extract raw bytes and send
    receipt = _send_signed_transaction_and_wait(signed)
    return receipt


def issue_certificate(submitter_private_key, cert_hash, owner, expiry):
    acct = w3.eth.account.from_key(submitter_private_key)

    tx = contract.functions.issueCertificate(
        HexBytes(cert_hash),
        Web3.to_checksum_address(owner),
        int(expiry),
    ).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 400000,
        "gasPrice": w3.eth.gas_price,
    })

    signed = w3.eth.account.sign_transaction(tx, private_key=submitter_private_key)
    receipt = _send_signed_transaction_and_wait(signed)
    return receipt


def revoke_certificate(submitter_private_key, cert_hash):
    acct = w3.eth.account.from_key(submitter_private_key)

    tx = contract.functions.revokeCertificate(HexBytes(cert_hash)).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 200000,
        "gasPrice": w3.eth.gas_price,
    })

    signed = w3.eth.account.sign_transaction(tx, private_key=submitter_private_key)
    receipt = _send_signed_transaction_and_wait(signed)
    return receipt


def _role_bytes32(role_name: str) -> bytes:
    # Accept either role name like "INSPECTOR_ROLE" or a bytes32 hex string
    if role_name.startswith("0x") and len(role_name) == 66:
        return HexBytes(role_name)
    return Web3.keccak(text=role_name)  # returns bytes

def grant_role(admin_private_key: str, role_name: str, target_address: str):
    acct = w3.eth.account.from_key(admin_private_key)
    role_b = _role_bytes32(role_name)
    tx = contract.functions.grantRole(role_b, Web3.to_checksum_address(target_address)).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 200000
    })
    signed = w3.eth.account.sign_transaction(tx, private_key=admin_private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash)

def revoke_role(admin_private_key: str, role_name: str, target_address: str):
    acct = w3.eth.account.from_key(admin_private_key)
    role_b = _role_bytes32(role_name)
    tx = contract.functions.revokeRole(role_b, Web3.to_checksum_address(target_address)).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 200000
    })
    signed = w3.eth.account.sign_transaction(tx, private_key=admin_private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash)

def has_role(role_name: str, address: str) -> bool:
    role_b = _role_bytes32(role_name)
    return contract.functions.hasRole(role_b, Web3.to_checksum_address(address)).call()

def check_inspection_onchain(content_hash_hex: str) -> bool:
    # contract has mapping seenInspections(bytes32) -> bool
    h = content_hash_hex if content_hash_hex.startswith("0x") else "0x" + content_hash_hex
    return contract.functions.seenInspections(HexBytes(h)).call()

def is_certificate_valid(cert_hash_hex: str) -> bool:
    h = cert_hash_hex if cert_hash_hex.startswith("0x") else "0x" + cert_hash_hex
    return contract.functions.isCertificateValid(HexBytes(h)).call()



# ================================
# app/blockchain.py additions
import time
from web3 import Web3

from typing import List, Dict, Any

# Ensure 'contract' exists: contract = w3.eth.contract(address=..., abi=ABI)

def _get_block_timestamp(block_number: int) -> int:
    b = w3.eth.get_block(block_number)
    return int(b.timestamp)

def _block_for_timestamp(ts: int, search_back_blocks: int = 20000) -> int:
    """
    Find an approximate block number whose timestamp <= ts.
    This is a simple binary-ish search from latest back; for dev use-blocks small.
    """
    latest = w3.eth.block_number
    if ts >= _get_block_timestamp(latest):
        return latest
    low = 0
    high = latest
    # binary search by timestamp
    while low < high:
        mid = (low + high) // 2
        t = _get_block_timestamp(mid)
        if t < ts:
            low = mid + 1
        else:
            high = mid
    return max(0, low - 1)

def fetch_events_from_chain(from_block: int | None = None, to_block: int | None = None) -> List[Dict[str, Any]]:
    """
    Fetch recent events from contract and convert to unified activity items.
    Defaults: from_block = latest - 5000, to_block = latest
    """
    latest = w3.eth.block_number
    if to_block is None:
        to_block = latest
    if from_block is None:
        from_block = max(0, latest - 5000)  # configurable default range

    events = []
    # Event: InspectionRecorded(bytes32 contentHash, bytes32 summaryHash, address inspector, uint256 ts, bytes meta)
    try:
        ev = contract.events.InspectionRecorded().get_logs(fromBlock=from_block, toBlock=to_block)
        for e in ev:
            args = e["args"]
            ts = int(args.get("ts") or 0)
            events.append({
                "type": "inspection_onchain",
                "timestamp": ts or _get_block_timestamp(e["blockNumber"]),
                "block_number": e["blockNumber"],
                "tx_hash": e["transactionHash"].hex(),
                "actor": args.get("inspector"),
                "subject": args.get("contentHash"),
                "details": {
                    "summaryHash": args.get("summaryHash"),
                    "meta": args.get("meta").hex() if isinstance(args.get("meta"), (bytes, bytearray)) else args.get("meta")
                }
            })
    except Exception:
        # ignore if event missing (older contract) or decode error
        pass

    # AgentAction(actionHash, agent, actionType, ts, meta)
    try:
        ev = contract.events.AgentAction().get_logs(fromBlock=from_block, toBlock=to_block)
        for e in ev:
            args = e["args"]
            events.append({
                "type": "agent_action_onchain",
                "timestamp": int(args.get("ts") or _get_block_timestamp(e["blockNumber"])),
                "block_number": e["blockNumber"],
                "tx_hash": e["transactionHash"].hex(),
                "actor": args.get("agent"),
                "subject": args.get("actionHash"),
                "details": {"actionType": args.get("actionType"), "meta": args.get("meta").hex() if isinstance(args.get("meta"), (bytes,bytearray)) else args.get("meta")}
            })
    except Exception:
        pass

    # CertificateIssued(certHash, issuer, owner, expiry)
    try:
        ev = contract.events.CertificateIssued().get_logs(fromBlock=from_block, toBlock=to_block)
        for e in ev:
            args = e["args"]
            events.append({
                "type": "certificate_issued_onchain",
                "timestamp": _get_block_timestamp(e["blockNumber"]),
                "block_number": e["blockNumber"],
                "tx_hash": e["transactionHash"].hex(),
                "actor": args.get("issuer"),
                "subject": args.get("certHash"),
                "details": {"owner": args.get("owner"), "expiry": int(args.get("expiry") or 0)}
            })
    except Exception:
        pass

    # CertificateRevoked(certHash, revokedBy, ts)
    try:
        ev = contract.events.CertificateRevoked().get_logs(fromBlock=from_block, toBlock=to_block)
        for e in ev:
            args = e["args"]
            events.append({
                "type": "certificate_revoked_onchain",
                "timestamp": int(args.get("ts") or _get_block_timestamp(e["blockNumber"])),
                "block_number": e["blockNumber"],
                "tx_hash": e["transactionHash"].hex(),
                "actor": args.get("revokedBy"),
                "subject": args.get("certHash"),
                "details": {}
            })
    except Exception:
        pass

    # PolicyChanged event if needed
    try:
        ev = contract.events.PolicyChanged().get_logs(fromBlock=from_block, toBlock=to_block)
        for e in ev:
            args = e["args"]
            events.append({
                "type": "policy_changed_onchain",
                "timestamp": _get_block_timestamp(e["blockNumber"]),
                "block_number": e["blockNumber"],
                "tx_hash": e["transactionHash"].hex(),
                "actor": args.get("changedBy"),
                "subject": args.get("policyKey"),
                "details": {}
            })
    except Exception:
        pass

    # RoleGranted and RoleRevoked (AccessControl emits RoleGranted/RoleRevoked)
    try:
        # topics for RoleGranted/Revoked are available via contract.events.RoleGranted
        ev = contract.events.RoleGranted().get_logs(fromBlock=from_block, toBlock=to_block)
        for e in ev:
            args = e["args"]
            role_hex = args.get("role")  # bytes32
            events.append({
                "type": "role_granted",
                "timestamp": _get_block_timestamp(e["blockNumber"]),
                "block_number": e["blockNumber"],
                "tx_hash": e["transactionHash"].hex(),
                "actor": args.get("account"),
                "subject": role_hex.hex() if hasattr(role_hex, "hex") else role_hex,
                "details": {"grantedBy": args.get("sender")}
            })
    except Exception:
        pass

    try:
        ev = contract.events.RoleRevoked().get_logs(fromBlock=from_block, toBlock=to_block)
        for e in ev:
            args = e["args"]
            role_hex = args.get("role")
            events.append({
                "type": "role_revoked",
                "timestamp": _get_block_timestamp(e["blockNumber"]),
                "block_number": e["blockNumber"],
                "tx_hash": e["transactionHash"].hex(),
                "actor": args.get("account"),
                "subject": role_hex.hex() if hasattr(role_hex, "hex") else role_hex,
                "details": {"revokedBy": args.get("sender")}
            })
    except Exception:
        pass

    # sort by timestamp for convenience
    events.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
    return events