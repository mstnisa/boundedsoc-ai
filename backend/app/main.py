from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import app.db.all_models  # noqa: F401 — ensure every model is registered before routes touch the ORM
from app.api.routes import admin, alerts, audit_logs, compliance, health, incidents, integrations
from app.core.config import get_settings
from app.db.session import SessionLocal
from app.services import mcp_gateway

settings = get_settings()

app = FastAPI(
    title="AI SOC Workbench",
    description=(
        "Explainable, human-in-the-loop security investigation automation. "
        "The AI assists; it never autonomously declares an incident malicious, "
        "isolates a system, blocks anything, or deletes evidence."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, tags=["health"])
app.include_router(alerts.router, tags=["alerts"])
app.include_router(incidents.router, tags=["incidents"])
app.include_router(audit_logs.router, tags=["audit"])
app.include_router(integrations.router, tags=["integrations"])
app.include_router(admin.router, tags=["admin"])
app.include_router(compliance.router, tags=["compliance"])


@app.on_event("startup")
def _seed_defaults() -> None:
    # Idempotent: seeds the two conservative default tool-access policies
    # (github: create_pr only; secret_provider: revoke only) so the MCP
    # gateway has something to check against out of the box. Never widens
    # an existing policy an admin has already changed.
    db = SessionLocal()
    try:
        mcp_gateway.ensure_default_policies(db)
    finally:
        db.close()
