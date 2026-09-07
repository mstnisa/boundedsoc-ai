# n8n workflow — orchestration only

This directory holds one importable n8n workflow: `soc_investigation_workflow.json`.

## What it does (and does not do)

The workflow sequences existing, audited FastAPI backend endpoints:

`Webhook (new alert ingested)` → `POST /incidents/{id}/extract-iocs` → `POST
/incidents/{id}/enrich` → `POST /incidents/{id}/severity-suggestion` → `POST
/incidents/{id}/mitre-suggestions` → `POST /incidents/{id}/report-draft` →
notify the SOC channel → a "human checkpoint" node that does nothing except
mark, in the n8n execution log, that everything past this point happens in
the AI SOC Workbench dashboard by a human analyst.

**n8n contains zero security logic.** It does not compute severity, does not
decide a verdict, does not call a real TI provider directly, and — critically
— it never approves, closes, or actions an incident. Every one of those
calls is the same backend code path the dashboard uses, so the audit trail,
evidence requirements, and guardrails in `app.ai` and `app.services` apply
identically whether the call was triggered by a human clicking a button or
by this workflow.

## Import instructions

1. Start the stack (`docker-compose up`) and open n8n at `http://localhost:5678`
   (basic-auth credentials from `.env`: `N8N_BASIC_AUTH_USER` / `N8N_BASIC_AUTH_PASSWORD`).
2. **Workflows → Import from File** → select `soc_investigation_workflow.json`.
3. Set two n8n environment variables (Settings → Variables, or via
   `docker-compose.yml` env passthrough):
   - `BACKEND_BASE_URL` — e.g. `http://backend:8000` (the Docker service name)
   - `NOTIFY_WEBHOOK_URL` — any webhook URL (Slack incoming webhook, a
     Microsoft Teams connector, or a local `https://webhook.site` URL for a
     demo). If you don't have one, point it at n8n's own test webhook so the
     workflow still runs end-to-end.
4. To trigger it, `POST` to the webhook n8n shows you (`/webhook/new-alert-ingested`)
   with `{"incident_id": "<uuid>"}` — for example, right after ingesting the
   demo scenario via `POST /alerts`, using the `incident_id` from that
   response.

## Why this exists as a separate, thin layer

The brief calls for n8n "for trigger → enrich → notify → human-checkpoint
flows only — keep all core security logic in Python services." Concretely
that means: if you deleted this workflow entirely, nothing about the
system's safety guarantees would change — you'd just have to call the same
five backend endpoints yourself (or via `POST /alerts`, which already
triggers correlation automatically). This workflow exists purely to save an
analyst the trouble of clicking through the same five buttons for every new
alert batch, and to push a "come look at this" notification into a chat
channel.
