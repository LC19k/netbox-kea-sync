from fastapi import APIRouter, Header, HTTPException, Request
import hashlib
import hmac
import json
import os

from .settings import settings
from .models import WebhookEvent
from .sync import sync_reservations

router = APIRouter()

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
    # LEGACY PROBE: Try all plausible NetBox-legacy variants
    # ------------------------------------------------------------
    if x_hook_signature:
        candidates = {}

        # 1) sha512(raw_body)
        candidates["sha512(raw_body)"] = hashlib.sha512(raw_body).hexdigest()

        # 2) HMAC-SHA512(secret, raw_body) if secret present
        if settings.webhook_secret:
            candidates["hmac_sha512(secret, raw_body)"] = hmac.new(
                key=settings.webhook_secret.encode(),
                msg=raw_body,
                digestmod=hashlib.sha512,
            ).hexdigest()

        # 3) sha512(canonical_json: sort_keys, no indent)
        try:
            parsed = json.loads(raw_body)
            canonical_min = json.dumps(parsed, separators=(",", ":"), sort_keys=True).encode()
            candidates["sha512(canonical_min)"] = hashlib.sha512(canonical_min).hexdigest()
        except Exception:
            pass

        # 4) sha512(pretty_json: sort_keys, indent=4)
        try:
            parsed = json.loads(raw_body)
            canonical_pretty = json.dumps(parsed, indent=4, sort_keys=True).encode()
            candidates["sha512(canonical_pretty)"] = hashlib.sha512(canonical_pretty).hexdigest()
        except Exception:
            pass

        print("LEGACY CANDIDATES:")
        for label, digest in candidates.items():
            print(f"  {label}: {digest}")
            if hmac.compare_digest(x_hook_signature, digest):
                print(f"--> MATCHED LEGACY MODE: {label}")
                return await handle_event(request)

        print("--> NO LEGACY CANDIDATE MATCHED HEADER")
        raise HTTPException(status_code=401, detail="Invalid legacy signature")

    # ------------------------------------------------------------
    # MODERN HMAC MODE (NetBox 4.x+)
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

    raise HTTPException(status_code=401, detail="Missing signature header")


async def handle_event(request: Request):
    data = await request.json()
    event = WebhookEvent(**data)

    if event.object_type in ["ipam.ipaddress", "ipam.prefix"]:
        await sync_reservations()

    return {"status": "ok"}
