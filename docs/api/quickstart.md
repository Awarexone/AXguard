# API Quickstart

```bash
pip install -e '.[api]'
axguard api start
curl -s http://127.0.0.1:8787/v1/health | python -m json.tool
```

Create a project and queue a lite scan:

```bash
curl -s -X POST http://127.0.0.1:8787/v1/projects \
  -H 'Content-Type: application/json' \
  -d '{"name":"demo","path":"."}'

curl -s -X POST http://127.0.0.1:8787/v1/projects/PROJECT_ID/scans \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: demo-1' \
  -d '{"mode":"lite","enrichment":"none"}'
```

Default bind: `127.0.0.1:8787`. SQLite state: `~/.axguard/api/api.db`.
