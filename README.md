# atlas-rule-engine ✅ (Completed: 2026-02-22)

Rule Engine for **PipelineAtlas** — deterministic CI/CD analysis with confidence-scored findings.

## Purpose

Queries the `atlas-graph` service and applies deterministic rule-based checks to detect CI/CD anti-patterns, risks, and improvement opportunities. Every finding includes evidence and a confidence score.

## Built-in Rule Categories

| Category | Examples |
|----------|---------|
| Performance | Missing caching, excessive sequential stages |
| Reliability | No timeouts, missing retry logic |
| Security | Unpinned Docker images, secret exposure risk |
| Complexity | Dynamic pipeline complexity, heavy shell usage |
| Documentation | Missing docs, artifact coupling risks |
| Dependencies | Cross-repo triggers, undeclared dependencies |

## Finding Structure

Each rule produces: Title, Description, Severity, Evidence, Confidence Score, Recommendation, Impact Category.

## Dependencies

- `atlas-sdk` (shared models)
- `redis` (Redis Streams)

## Related Services

Queries ← `atlas-graph`
Publishes to → `atlas-report`
