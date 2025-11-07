# app/tasks.py
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from app.crud import get_valid_certificates, mark_certificate_revoked
from app.blockchain import revoke_certificate
from app.settings import settings
import time

log = logging.getLogger("tasks")

def check_expiry_and_revoke():
    log.info("Running expiry check...")
    now = int(time.time())
    threshold = settings.AUTO_REVOKE_DAYS_BEFORE * 24 * 3600
    certs = get_valid_certificates()
    for c in certs:
        if c.expiry is None:
            continue
        if now >= c.expiry:
            log.info("Auto-revoking cert:", c.cert_hash)
            # call blockchain revoke (use ADMIN or SUBMITTER PK)
            try:
                receipt = revoke_certificate(settings.ADMIN_PK, c.cert_hash)
                mark_certificate_revoked(c.cert_hash)
                log.info("Revoked on-chain:", receipt.transactionHash.hex())
            except Exception as e:
                log.exception("Revoke failed", e)
        elif now >= (c.expiry - threshold):
            # here you could send a reminder (email/sms)
            log.info("Certificate will expire soon:", c.cert_hash)

scheduler = BackgroundScheduler()
scheduler.add_job(check_expiry_and_revoke, "interval", minutes=10)
