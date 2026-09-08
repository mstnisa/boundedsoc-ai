# Contributing

Thanks for considering a contribution to BoundedSOC AI. This is a
portfolio/research project built around a specific, non-negotiable
principle: **the AI assists, it never decides.** Any contribution that
weakens that boundary (autonomous response actions, AI claims without
evidence, bypassing human review) will not be accepted, however useful it
seems.

## Getting set up

```bash
git clone https://github.com/mstnisa/boundedsoc-ai.git
cd boundedsoc-ai
cp .env.example .env   # edit if you want non-default values; defaults work out of the box
docker-compose up
```

- Backend: FastAPI at `http://localhost:8000` (docs at `/docs`)
- Frontend: React dashboard at `http://localhost:5173`
- n8n: `http://localhost:5678`

For backend-only local development without Docker:

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload
```

For frontend-only local development:

```bash
cd frontend
npm install
npm run dev
```

## Running tests

```bash
cd backend
export TEST_DATABASE_URL=postgresql+psycopg2://soc_admin:<pw>@localhost:5432/soc_workbench_test
pytest -q --cov=app
ruff check app tests
black --check app tests
```

```bash
cd frontend
npx tsc -b
npx vite build
```

## Code organization

- `backend/app/models/` — SQLAlchemy models (the schema)
- `backend/app/services/` — deterministic business logic (normalization,
  extraction, correlation, timeline, enrichment, review, export, audit)
- `backend/app/ai/` — the bounded AI layer: provider interface, mock
  provider, guardrails, prompts, LangGraph orchestration
- `backend/app/api/routes/` — FastAPI endpoints (thin — they call services,
  they don't contain business logic)
- `backend/tests/` — unit / api / integration / adversarial / regression,
  see each directory's docstrings
- `frontend/src/` — React + TypeScript dashboard
- `n8n/` — one importable workflow (orchestration only, see `n8n/README.md`)
- `scripts/benchmark.py` — the measurement plan, runs against a live backend
- `data/` — synthetic demo data, bundled MITRE/Sigma reference subsets, the
  hand-labeled eval set

## Pull request expectations

1. New backend code that touches a service or route needs a test in the
   matching `tests/` subdirectory. `ruff` and `black` must pass clean.
2. Any new AI-generated claim type (a new suggestion kind, a new report
   section source) must follow the same pattern as existing ones: Pydantic
   structured output, mandatory non-empty `evidence_refs`, an audit log
   entry on both success and on drop-for-missing-evidence, and a human
   review path. See `app/services/ai_orchestration.py` as the reference
   implementation.
3. If you add a new threat-intel or LLM provider, it must default to
   *not* making real network calls — mock-by-default, live opt-in via
   `.env`, following `app/adapters/mock_virustotal.py` /
   `app/adapters/live_http_adapter.py` as the pattern.
4. If your change affects the measured numbers in
   `docs/benchmark_results.md`, re-run `python scripts/benchmark.py`
   against your local stack and include the refreshed output — don't hand-edit
   the numbers.
5. Nothing in the "Explicitly Do NOT Build" list in the README (autonomous
   host isolation, automatic blocking, destructive remediation, etc.) is
   ever in scope for a PR here, regardless of how the feature request is
   framed.

## Reporting bugs / requesting features

Open a GitHub issue. For anything touching the safety guarantees above
(evidence requirements, human-review gating, prompt-injection handling),
please say so explicitly in the issue so it gets the scrutiny it needs.
