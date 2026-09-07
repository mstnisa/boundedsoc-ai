# Roadmap

What's deliberately out of scope for v0.1 and why, grouped by what would
actually move this system forward versus what would just add surface area.

## Near-term (would meaningfully close a measured gap)

- **Measure human correction rate for real.** The infrastructure exists
  (`analyst_reviews`, `audit_logs`) — what's missing is real analyst usage
  over time. This is the single highest-value next step: it's the number
  the README explicitly flags as unmeasured, and it's the one that would
  actually validate (or invalidate) whether the AI suggestions are useful in
  practice, not just evidence-clean.
- **Time a real manual investigation** against the same eval cases, with an
  actual analyst and a stopwatch, to replace the documented-but-unmeasured
  step-count comparison in `docs/benchmark_results.md` with a real timing
  comparison. Current numbers are honestly labeled as not this — this is
  the fix, not a rewording.
- **Expand the eval set past 5 cases.** Enough to prove the pipeline and
  guardrails work end-to-end; not enough to make a strong statistical claim
  about MITRE suggestion accuracy in general. 30-50 hand-labeled cases
  across more technique categories would make that number mean more.
- **A production-grade auth mode.** `AUTH_SINGLE_USER_MODE` is an explicit,
  documented demo shortcut — real multi-analyst deployment needs real user
  management, not just "set the flag to false" (which currently has no
  populated alternative to fall back to).

## Medium-term (real capability, real complexity)

- **ML-assisted IOC extraction** as an optional layer alongside (not
  replacing) the current regex extractor — regex stays as the fast,
  fully-explainable default; a model-based extractor would be opt-in for
  catching obfuscated/novel indicator formats, with its own evidence trail.
- **Graph-based correlation** as an alternative to host+time-window grouping
  for multi-host campaigns, where the current simple grouping under- or
  over-groups. This is a genuinely harder problem to keep explainable, so
  it stays a "someday" item until there's a design that doesn't trade away
  the auditability the current approach has.
- **Database-level audit log immutability** (append-only table permissions,
  or a hash-chained log) instead of today's application-level-only
  append-only discipline — closes the residual Tampering risk noted in
  `docs/threat-model.md`.
- **Rate limiting and body-size caps on `POST /alerts`** for a real
  internet-facing ingestion path (today's rate limiting only covers
  outbound enrichment calls).
- **pgvector/RAG retrieval** over historical incidents or a larger MITRE/CTI
  corpus — deliberately skipped for v0.1 per the original design brief
  ("only if it measurably helps") because the bundled 8-technique reference
  subset and evidence-context approach already cover the demo scenarios
  without it. Worth revisiting once there's enough historical incident
  volume that retrieval would plausibly change an answer.

## Won't build (not a roadmap item — a boundary)

Autonomous host isolation, automatic firewall/EDR blocking, credential
actions, or any other automated response action. This isn't a "v2 feature"
sitting on a backlog — it's the boundary the whole project is designed
around (see the README's Core Principle and `docs/threat-model.md`'s
Non-threats section). If this ever changes, it changes what this project
is, not what version it's at.

## Housekeeping (small, low-risk, not urgent)

- Resolve the remaining Starlette dependency advisories once a FastAPI
  release supports the fixed Starlette version (tracked in `SECURITY.md`;
  blocked upstream, not by anything in this repo).
- Bump Vite past its current major version to clear the two remaining
  dev-server-only `npm audit` findings — deferred because it's a breaking
  config change, not because the findings are being ignored.
- Verify `docker-compose up` end-to-end in a network environment with
  normal Docker Hub access (see the Limitations section in the README for
  why this wasn't completed in this repo's original development
  environment).
