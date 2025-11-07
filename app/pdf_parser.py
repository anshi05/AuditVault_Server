"""
pdf_certificate_parser.py

Parses an inspection certificate PDF and extracts:
{
  "cert_id": "string",
  "owner": "string",
  "expiry_date": 0   # unix timestamp (seconds)
}

Strategy:
1. Try to extract text using pdfplumber (fast, preferred).
2. Use regex patterns to locate Certificate No, Client / Owner, Inspection Date,
   Expiry/Valid Until fields.
3. If expiry not present, compute expiry = inspection_date + 365 days.
4. If pdfplumber yields no text, optionally fallback to OCR (pytesseract).
"""

from typing import Optional, Dict
import pdfplumber
import re
from dateutil import parser as dateparser
from datetime import datetime, timedelta
import pytesseract
from PIL import Image
import io
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Regex patterns (case-insensitive)
CERT_REGEXES = [
    r"Certificate\s*No\.?\s*[:\-]?\s*([A-Za-z0-9\-\_/]+)",
    r"Certificate\s*Number\s*[:\-]?\s*([A-Za-z0-9\-\_/]+)",
    r"Cert\s*No\.?\s*[:\-]?\s*([A-Za-z0-9\-\_/]+)"
]

OWNER_REGEXES = [
    r"Client\s*[:\-]?\s*([A-Za-z0-9\.,&\-\s]+)",
    r"Owner\s*[:\-]?\s*([A-Za-z0-9\.,&\-\s]+)",
    r"Company\s*[:\-]?\s*([A-Za-z0-9\.,&\-\s]+)"
]

INSPECTION_DATE_REGEXES = [
    r"Inspection\s*Date\s*[:\-]?\s*([A-Za-z0-9,\-\s\/]+)",
    r"Date\s*[:\-]?\s*([A-Za-z0-9,\-\s\/]+)"
]

EXPIRY_REGEXES = [
    r"Expiry\s*(?:Date)?\s*[:\-]?\s*([A-Za-z0-9,\-\s\/]+)",
    r"Valid\s*(?:until|till)\s*[:\-]?\s*([A-Za-z0-9,\-\s\/]+)",
    r"Valid\s*Thru\s*[:\-]?\s*([A-Za-z0-9,\-\s\/]+)"
]

# helper: safely parse date-like strings
def parse_date_safe(date_str: str) -> Optional[datetime]:
    if not date_str:
        return None
    date_str = date_str.strip().replace('\n', ' ')
    try:
        # dateutil can handle many formats
        dt = dateparser.parse(date_str, dayfirst=False, yearfirst=False, fuzzy=True)
        return dt
    except Exception:
        try:
            # try dayfirst fallback
            dt = dateparser.parse(date_str, dayfirst=True, fuzzy=True)
            return dt
        except Exception:
            return None

def text_from_pdf(pdf_path: str) -> str:
    """Extract text using pdfplumber (text-based PDFs)."""
    text_parts = []
    try:
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)
    except Exception as e:
        logger.warning("pdfplumber failed: %s", e)
    return "\n".join(text_parts).strip()

def ocr_pdf_first_page(pdf_path: str) -> str:
    """Fallback: render first page to image and OCR it with pytesseract."""
    try:
        import pdfplumber
        with pdfplumber.open(pdf_path) as pdf:
            if len(pdf.pages) == 0:
                return ""
            page = pdf.pages[0]
            # render page to PIL image (higher resolution recommended for OCR)
            pil_image = page.to_image(resolution=200).original
            text = pytesseract.image_to_string(pil_image)
            return text
    except Exception as e:
        logger.warning("OCR fallback failed: %s", e)
        return ""

def find_first_match(text: str, patterns: list) -> Optional[str]:
    if not text:
        return None
    for pat in patterns:
        m = re.search(pat, text, flags=re.IGNORECASE)
        if m:
            # prefer first capturing group if present
            if m.groups():
                return m.group(1).strip()
            return m.group(0).strip()
    return None

def parse_certificate(pdf_path: str) -> Dict[str, object]:
    """
    Main parser function.
    Returns dict with keys 'cert_id', 'owner', 'expiry_date' (unix seconds).
    """
    text = text_from_pdf(pdf_path)
    used_ocr = False
    if not text:
        logger.info("No text extracted by pdfplumber, using OCR fallback.")
        text = ocr_pdf_first_page(pdf_path)
        used_ocr = True

    if not text:
        # nothing to extract
        logger.error("No textual content found in PDF.")
        return {"cert_id": "", "owner": "", "expiry_date": 0}

    # Extract certificate id
    cert_id = find_first_match(text, CERT_REGEXES) or ""
    # try an inline fallback: look for patterns like TI-IC-2025-0112 directly
    if not cert_id:
        m = re.search(r"[A-Z]{1,5}[-_][A-Z]{1,5}[-_]\d{4}[-_]\d{3,6}", text)
        if m:
            cert_id = m.group(0)

    # Extract owner/client
    owner_raw = find_first_match(text, OWNER_REGEXES) or ""
    # Sometimes owner appears as 'Client: ABC Constructions Ltd.'
    owner = owner_raw.strip()

    # Extract inspection date
    insp_date_str = find_first_match(text, INSPECTION_DATE_REGEXES) or ""
    inspection_date = parse_date_safe(insp_date_str)

    # Extract explicit expiry if present
    expiry_str = find_first_match(text, EXPIRY_REGEXES) or ""
    expiry_date_dt = parse_date_safe(expiry_str)

    # If expiry not found, try to find "valid for X months/years" patterns
    if expiry_date_dt is None:
        m = re.search(r"valid\s*for\s*(\d+)\s*(months|month|years|year)", text, flags=re.IGNORECASE)
        if m:
            n = int(m.group(1))
            unit = m.group(2).lower()
            if inspection_date:
                if 'year' in unit:
                    expiry_date_dt = inspection_date + timedelta(days=365 * n)
                else:
                    expiry_date_dt = inspection_date + timedelta(days=30 * n)

    # Default fallback: if no expiry but we have inspection date, expiry = inspection_date + 365 days
    if expiry_date_dt is None and inspection_date:
        expiry_date_dt = inspection_date + timedelta(days=365)

    # Final conversions: timestamps in seconds
    expiry_ts = 0
    if expiry_date_dt:
        expiry_ts = int(expiry_date_dt.replace(tzinfo=None).timestamp())

    # If owner still empty, try heuristics: near "Client:" or first lines after header
    if not owner:
        lines = text.splitlines()
        # attempt to find a line containing 'Client' then take the rest of the line
        for ln in lines:
            if 'client' in ln.lower() or 'owner' in ln.lower() or 'company' in ln.lower():
                parts = ln.split(':', 1)
                if len(parts) > 1:
                    owner = parts[1].strip()
                    break
        # fallback: pick a line that looks like a company (contains Ltd, Pvt, Inc, LLC)
        if not owner:
            for ln in lines:
                if re.search(r"\b(Ltd|Pvt|Private|Inc|LLC|Limited|Corporation)\b", ln, flags=re.IGNORECASE):
                    owner = ln.strip()
                    break

    return {
        "cert_id": cert_id,
        "owner": owner,
        "expiry_date": expiry_ts
    }

# If run as script, demonstrate on sample file path
if __name__ == "__main__":
    import json
    sample_pdf = "/mnt/data/sample_inspection_certificate.pdf"  # change if needed
    result = parse_certificate(sample_pdf)
    print(json.dumps(result, indent=2))
