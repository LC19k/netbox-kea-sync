from fastapi import APIRouter, Header, HTTPException, Request
import hashlib
import hmac
import json
import os

from .settings import settings
from .models import WebhookEvent
from .sync import sync_reservations

router = APIRouter()

# Enable hex-dump debugging with WEBHOOK_DEBUG=1
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

    # ------------------------------------------------------------
    # MODE A: NetBox CE / Legacy Mode
    # Header: X-Hook-Signature
    # Value: sha512(pretty_printed_sorted_json)
    # ------------------------------------------------------------
    if x_hook_signature:
        try:
            parsed = json.loads(raw_body)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        # Reconstruct EXACTLY what NetBox CE signs internally
        canonical = json.dumps(
            parsed,
            indent=4,          # NetBox CE uses pretty-printed JSON
            sort_keys=True     # NetBox CE sorts keys before hashing
        ).encode()

        expected = hashlib.sha512(canonical).hexdigest()

        if not hmac.compare_digest(x_hook_signature, expected):
            raise HTTPException(status_code=401, detail="Invalid legacy signature")

        return await handle_event(request)

    # ------------------------------------------------------------
    # MODE B: Modern HMAC Mode (NetBox 4.x+)
    # Header: X-Webhook-Signature
    # Value: sha256=<hmac(secret, raw_body)>
    # ------------------------------------------------------------
    if x_webhook_signature:
        if not x_webhook_signature.startswith("sha256="):
            raise HTTPException(status_code=401, detail="Invalid signature format")

        sent = x_webhook_signature.split("=", 1)[1]

        expected = hmac.new(
            key=settings.webhook_secret.encode(),
            msg=raw_body,
            digestmod=hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(sent, expected):
            raise HTTPException(status_code=401, detail="Invalid HMAC signature")

        return await handle_event(request)

    # ------------------------------------------------------------
    # MODE C: No signature at all
    # ------------------------------------------------------------
    raise HTTPException(status_code=401, detail="Missing signature header")


async def handle_event(request: Request):
    """Shared event handler after signature validation."""
    data = await request.json()
    event = WebhookEvent(**data)

    if event.object_type in ["ipam.ipaddress", "ipam.prefix"]:
        await sync_reservations()

    return {"status": "ok"}
