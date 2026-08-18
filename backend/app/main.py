from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import SessionLocal, ensure_columns
from app.migrate import apply_schema
from app.routers import (
    admin,
    agent_api,
    agents,
    alerts,
    assets,
    auth,
    compliance,
    devices,
    exclusions,
    findings,
    networks,
    scans,
    scanner_api,
    sites,
    subnets,
    tenants,
    treatments,
    users,
    wan_targets,
)
from app.scheduler import start_scheduler
from app.inventory import refresh_discovery_metadata
from app.seed import seed


@asynccontextmanager
async def lifespan(_: FastAPI):
    apply_schema()
    # Retained until existing-install adoption is proven. Do not add new ALTER TABLE here.
    ensure_columns()
    db = SessionLocal()
    try:
        seed(db)
        refresh_discovery_metadata(db)
    finally:
        db.close()
    start_scheduler()
    yield


app = FastAPI(title="Nuclei Dashboard", lifespan=lifespan)
origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins or ["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth")
app.include_router(users.router, prefix="/api")
app.include_router(tenants.router, prefix="/api")
app.include_router(sites.router, prefix="/api")
app.include_router(networks.router, prefix="/api")
app.include_router(subnets.router, prefix="/api")
app.include_router(agents.router, prefix="/api")
app.include_router(scans.router, prefix="/api")
app.include_router(wan_targets.router, prefix="/api")
app.include_router(exclusions.router, prefix="/api")
app.include_router(devices.router, prefix="/api")
app.include_router(assets.router, prefix="/api")
app.include_router(findings.router, prefix="/api")
app.include_router(treatments.router, prefix="/api")
app.include_router(compliance.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(admin.router, prefix="/api")
app.include_router(agent_api.router, prefix="/api")
app.include_router(scanner_api.router, prefix="/api")


@app.get("/api/health")
def health():
    return {"ok": True}
