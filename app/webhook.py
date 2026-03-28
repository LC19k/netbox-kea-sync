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


def sha512(data):
    return hashlib.sha512(data).hexdigest()


def hmac512(key, data):
    return hmac.new(key, data, hashlib.sha512).hexdigest()


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

    # ============================================================
    # MODE A — LEGACY SIGNATURE (X-Hook-Signature)
    # ============================================================
    if x_hook_signature:
        print("\n=== BEGIN LEGACY SIGNATURE PROBE ===")

        candidates = {}

        # --- RAW BODY VARIANTS ---
        candidates["sha512(raw_body)"] = sha512(raw_body)
        candidates["sha512(raw_body.strip())"] = sha512(raw_body.strip())
        candidates["sha512(raw_body + b'\\n')"] = sha512(raw_body + b"\n")
        candidates["sha512(raw_body CRLF)"] = sha512(raw_body.replace(b"\n", b"\r\n"))

        # --- ENCODING VARIANTS ---
        try:
            decoded = raw_body.decode()
            candidates["sha512(utf8-sig)"] = sha512(decoded.encode("utf-8-sig"))
            candidates["sha512(utf16)"] = sha512(decoded.encode("utf-16"))
            candidates["sha512(utf16-le)"] = sha512(decoded.encode("utf-16-le"))
            candidates["sha512(utf16-be)"] = sha512(decoded.encode("utf-16-be"))
        except Exception:
            pass

        # --- JSON VARIANTS ---
        try:
            parsed = json.loads(raw_body)

            # Minified sorted
            canonical_min = json.dumps(parsed, separators=(",", ":"), sort_keys=True).encode()
            candidates["sha512(canonical_min)"] = sha512(canonical_min)

            # Pretty sorted (indent=4)
            canonical_pretty = json.dumps(parsed, indent=4, sort_keys=True).encode()
            candidates["sha512(canonical_pretty)"] = sha512(canonical_pretty)

            # Pretty sorted (indent=2)
            canonical_pretty2 = json.dumps(parsed, indent=2, sort_keys=True).encode()
            candidates["sha512(canonical_pretty2)"] = sha512(canonical_pretty2)

            # Pretty sorted (indent=1)
            canonical_pretty1 = json.dumps(parsed, indent=1, sort_keys=True).encode()
            candidates["sha512(canonical_pretty1)"] = sha512(canonical_pretty1)

            # Pretty sorted (indent=0)
            canonical_pretty0 = json.dumps(parsed, indent=0, sort_keys=True).encode()
            candidates["sha512(canonical_pretty0)"] = sha512(canonical_pretty0)

            # repr() and str()
            candidates["sha512(repr(parsed))"] = sha512(repr(parsed).encode())
            candidates["sha512(str(parsed))"] = sha512(str(parsed).encode())

        except Exception:
            pass

        # --- HMAC VARIANTS ---
        if settings.webhook_secret:
            key_utf8 = settings.webhook_secret.encode()
            key_utf16 = settings.webhook_secret.encode("utf-16")
            key_utf16le = settings.webhook_secret.encode("utf-16-le")
            key_utf16be = settings.webhook_secret.encode("utf-16-be")

            # Raw body HMACs
            candidates["hmac512(secret, raw_body)"] = hmac512(key_utf8, raw_body)
            candidates["hmac512(secret, raw_body.strip())"] = hmac512(key_utf8, raw_body.strip())
            candidates["hmac512(secret, raw_body + b'\\n')"] = hmac512(key_utf8, raw_body + b"\n")
            candidates["hmac512(secret, raw_body CRLF)"] = hmac512(key_utf8, raw_body.replace(b"\n", b"\r\n"))

            # HMAC with alternate encodings
            candidates["hmac512(secret_utf16, raw_body)"] = hmac512(key_utf16, raw_body)
            candidates["hmac512(secret_utf16le, raw_body)"] = hmac512(key_utf16le, raw_body)
            candidates["hmac512(secret_utf16be, raw_body)"] = hmac512(key_utf16be, raw_body)

            # HMAC with canonical JSON
            try:
                candidates["hmac512(secret, canonical_min)"] = hmac512(key_utf8, canonical_min)
                candidates["hmac512(secret, canonical_pretty)"] = hmac512(key_utf8, canonical_pretty)
            except Exception:
                pass

        # --- LOG AND MATCH ---
        for label, digest in candidates.items():
            print(f"{label}: {digest}")
            if hmac.compare_digest(x_hook_signature, digest):
                print(f"\n--> MATCHED LEGACY MODE: {label}\n")
                return await handle_event(request)

        print("\n--> NO LEGACY CANDIDATE MATCHED HEADER\n")
        raise HTTPException(status_code=401, detail="Invalid legacy signature")

    # ============================================================
    # MODE B — MODERN SIGNATURE (X-Webhook-Signature)
    # ============================================================
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

    # ============================================================
    # NO SIGNATURE PROVIDED
    # ============================================================
    raise HTTPException(status_code=401, detail="Missing signature header")


async def handle_event(request: Request):
    data = await request.json()
    event = WebhookEvent(**data)

    if event.object_type in ["ipam.ipaddress", "ipam.prefix"]:
        await sync_reservations()

    return {"status": "ok"}
