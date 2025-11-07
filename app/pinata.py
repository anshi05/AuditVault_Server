# app/pinata.py
import requests, os
from .settings import settings
from typing import Optional, Dict
import json

PINATA_BASE_URL = "https://api.pinata.cloud"
PIN_FILE_URL = f"{PINATA_BASE_URL}/pinning/pinFileToIPFS"
PIN_JSON_URL = f"{PINATA_BASE_URL}/pinning/pinJSONToIPFS"

def _auth_headers() -> Dict[str, str]:
    """
    Build authorization headers for Pinata.
    """
    headers = {}
    if getattr(settings, "PINATA_JWT", None):
        headers["Authorization"] = f"Bearer {settings.PINATA_JWT}"
    elif getattr(settings, "PINATA_API_KEY", None) and getattr(settings, "PINATA_API_SECRET", None):
        headers["pinata_api_key"] = settings.PINATA_API_KEY
        headers["pinata_secret_api_key"] = settings.PINATA_API_SECRET
    else:
        raise ValueError("Pinata credentials not configured properly in .env")
    return headers


def pin_file(file_path: str, metadata: Optional[dict] = None) -> dict:
    """
    Uploads a file to Pinata and returns the API JSON response.
    """
    try:
        headers = _auth_headers()
        with open(file_path, "rb") as fp:
            files = {"file": fp}
            payload = {}
            if metadata:
                payload["pinataMetadata"] = json.dumps(metadata)

            res = requests.post(PIN_FILE_URL, files=files, data=payload, headers=headers, timeout=60)
            res.raise_for_status()
            return res.json()

    except Exception as e:
        raise Exception(f"Pinata file upload failed: {e}")


def pin_json(data: dict, metadata: Optional[dict] = None) -> dict:
    """
    Pins JSON data to Pinata.
    """
    try:
        headers = _auth_headers()
        headers["Content-Type"] = "application/json"

        payload = {"pinataContent": data}
        if metadata:
            payload["pinataMetadata"] = metadata

        res = requests.post(PIN_JSON_URL, headers=headers, data=json.dumps(payload), timeout=60)
        res.raise_for_status()
        return res.json()

    except Exception as e:
        raise Exception(f"Pinata JSON upload failed: {e}")