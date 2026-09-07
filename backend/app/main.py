from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import app.db.all_models  # noqa: F401 — ensure every model is registered before routes touch the ORM
from app.api.routes import alerts, audit_logs, health, incidents, integrations
from app.core.config import get_settings

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
