from fastapi import FastAPI
from .webhook import router as webhook_router
from .sync import sync_reservations

app = FastAPI()

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/sync-now")
async def sync_now():
    await sync_reservations()
    return {"status": "synced"}

app.include_router(webhook_router)
