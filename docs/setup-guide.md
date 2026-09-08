# Setup Guide

Two paths: Docker Compose (one command, recommended) or running each piece
natively (useful for development, or if your environment can't pull public
Docker images — see the note at the bottom).

## Prerequisites

- Docker + Docker Compose v2, **or** Python 3.12+, Node 20+, and a local
  PostgreSQL 16 for the native path.
- No paid API keys of any kind. Everything defaults to mocked providers.

## Path 1: Docker Compose

```bash
git clone https://github.com/mstnisa/boundedsoc-ai.git
cd boundedsoc-ai
cp .env.example .env
docker-compose up
```

This starts five services:

| Service | URL | Notes |
|---|---|---|
| `db` | internal `5432` | PostgreSQL 16, healthchecked before `backend` starts |
| `redis` | internal `6379` | Available for caching; the app also has an in-process cache fallback |
| `backend` | `http://localhost:8000` | Runs `alembic upgrade head` then `uvicorn` on container start — migrations are automatic |
| `frontend` | `http://localhost:5173` | React dashboard |
| `n8n` | `http://localhost:5678` | Default login `admin` / `change-me` — **change this in `.env` before exposing it beyond localhost** |

Interactive API docs: `http://localhost:8000/docs`.

Stop everything with `docker-compose down` (add `-v` to also drop the
database volume and start fresh).

## Path 2: Native (no Docker)

Useful for active development, or in a network environment that can't reach
Docker Hub.

### 1. Database

```bash
# Any local PostgreSQL 16 works. Example using createuser/createdb:
createuser soc_admin -P        # set a password when prompted
createdb soc_workbench -O soc_admin
```

### 2. Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# .env in the repo root (or backend/, both are read) needs DATABASE_URL
# pointed at your local Postgres, e.g.:
#   DATABASE_URL=postgresql+psycopg2://soc_admin:<pw>@localhost:5432/soc_workbench

alembic upgrade head
uvicorn app.main:app --reload
```

The API is now at `http://localhost:8000`.

### 3. Frontend

```bash
cd frontend
npm install
npm run dev
```

The dashboard is now at `http://localhost:5173` (Vite dev server) and talks
to the backend via `VITE_API_BASE_URL` in `frontend/.env`.

### 4. n8n (optional)

n8n is orchestration convenience, not a dependency — the API is fully usable
without it. To try the workflow:

```bash
npx n8n
# then import n8n/soc_investigation_workflow.json via the n8n UI
```

## Loading the demo scenario

Once the backend is running (either path):

```bash
curl -X POST http://localhost:8000/alerts \
  -H "Content-Type: application/json" \
  -d @data/synthetic/demo_incident_powershell.json
```

Then open the dashboard, or continue the walkthrough in
`docs/demo-walkthrough.md`.

## Running tests

```bash
cd backend
# Requires a reachable Postgres; the test suite creates/truncates its own schema.
export TEST_DATABASE_URL=postgresql+psycopg2://soc_admin:<pw>@localhost:5432/soc_workbench_test
pytest -q --cov=app
ruff check app tests
black --check app tests
```

## Running the benchmark

```bash
# backend must be running (either path above)
cd backend
python ../scripts/benchmark.py
```

This overwrites `data/eval/benchmark_results.json` and
`docs/benchmark_results.md` with a fresh run against whatever's currently
running — real numbers, not cached ones.

## Configuration reference

All configuration is environment variables, documented with defaults and
comments in `.env.example`. The ones worth knowing about up front:

- `AUTH_SINGLE_USER_MODE` (default `true`) — bypasses JWT auth to a fixed
  local demo identity. Set to `false` and configure real auth before any
  multi-user or internet-facing deployment.
- `LLM_PROVIDER` (default `mock`) — `mock`, `openai`, or `anthropic`.
  Switching off `mock` requires the matching API key and is the only way
  any AI feature in this repo makes a real network call to an LLM.
- `TI_USE_LIVE_PROVIDERS` (default `false`) — when `false`, VirusTotal- and
  AbuseIPDB-style enrichment is fully mocked and deterministic. Flip
  per-provider only if you have real API keys and want real lookups.

## A note on `docker-compose up` in restricted network environments

The Dockerfiles here pull standard public base images
(`postgres:16-alpine`, `redis:7-alpine`, `python:3.12-slim`,
`node:20-alpine`, `n8nio/n8n:latest`). If your network blocks Docker Hub
(some corporate/sandboxed environments do), `docker-compose up` will fail at
the image-pull step, not because of anything wrong in this repo's
configuration. In that situation, use Path 2 (native) above, or point Docker
at a registry mirror your environment allows. This exact limitation is why
this repo's own README documents that the full composed stack was verified
via the native-equivalent commands rather than a live `docker-compose up`
run in its original development environment — see the Limitations section
there.
