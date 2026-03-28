from fastapi import APIRouter, Header, HTTPException, Request
import hashlib
import hmac
import json
import os

from .settings import settings
from .models import WebhookEvent
from .sync import sync_reservations

router = APIRouter()

# ============================================================
# STARTUP SECRET CHECK
# ============================================================
print("=== STARTUP SECRET CHECK ===")
print(f"WEBHOOK_SECRET (len={len(settings.webhook_secret)}): {repr(settings.webhook_secret)}")
print("=== END SECRET CHECK ===")

DEBUG = os.getenv("WEBHOOK_DEBUG", "0") == "1"

@router.post("/webhook")
async def webhook(
    request: Request,
    x_hook_signature: str = Header(None, alias="X-Hook-Signature"),
    x_webhook_signature: str = Header(None, alias="X-Webhook-Signature"),
):
    headers = dict(request.headers)
    print("HEADERS:", headers)

    raw_body = await request.body()

    if DEBUG:
        print("RAW BODY HEX:", raw_body.hex())

    secret = settings.webhook_secret
    if not secret:
        raise HTTPException(status_code=500, detail="WEBHOOK_SECRET not configured")

    key = secret.encode()

    # ------------------------------------------------------------
    # Legacy mode: X-Hook-Signature (HMAC-SHA512 over raw body)
    # ------------------------------------------------------------
    if x_hook_signature:
        expected = hmac.new(
            key=key,
            msg=raw_body,
            digestmod=hashlib.sha512,
        ).hexdigest()

        if not hmac.compare_digest(x_hook_signature, expected):
            raise HTTPException(status_code=401, detail="Invalid legacy signature")

        return await handle_event(request)

    # ------------------------------------------------------------
    # Modern mode: X-Webhook-Signature (sha256=<HMAC-SHA256>)
    # ------------------------------------------------------------
    if x_webhook_signature:
        if not x_webhook_signature.startswith("sha256="):
            raise HTTPException(status_code=401, detail="Invalid signature format")

        sent = x_webhook_signature.split("=", 1)[1]

        expected = hmac.new(
            key=key,
            msg=raw_body,
            digestmod=hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(sent, expected):
            raise HTTPException(status_code=401, detail="Invalid HMAC signature")

        return await handle_event(request)

    raise HTTPException(status_code=401, detail="Missing signature header")


async def handle_event(request: Request):
    data = await request.json()
    event = WebhookEvent(**data)

    if event.object_type in ["ipam.ipaddress", "ipam.prefix"]:
        await sync_reservations()

    return {"status": "ok"}
