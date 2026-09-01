from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.security_headers import SecurityHeadersMiddleware

from app.bootstrap import run_api_bootstrap
from app.config import settings
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
    history,
    networks,
    policies,
    reports,
    scans,
    scanner_api,
    sites,
    subnets,
    tenants,
    treatments,
    users,
    wan_targets,
)
from app.seed import seed


def prepare_control_plane(db) -> None:
    """API process bootstrap. Must stay independent of Device inventory size.

    Device classification/auto_label/tech catch-up is a bounded scheduler page
    in the dedicated scheduler process, not a startup table scan.
    """
    seed(db)


@asynccontextmanager
async def lifespan(_: FastAPI):
    run_api_bootstrap()
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
app.add_middleware(SecurityHeadersMiddleware)

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
app.include_router(policies.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(alerts.events_router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(history.router, prefix="/api")
app.include_router(admin.router, prefix="/api")
app.include_router(agent_api.router, prefix="/api")
app.include_router(scanner_api.router, prefix="/api")


@app.get("/api/health")
def health():
    return {"ok": True}
