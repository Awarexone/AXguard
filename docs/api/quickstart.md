# API quickstart

No account. No AwareXone login. No mandatory LLM.

```bash
pip install -e '.[api]'
axguard api start
```

```bash
curl http://127.0.0.1:8787/v1/health

curl -s -X POST http://127.0.0.1:8787/v1/projects \
  -H 'Content-Type: application/json' \
  -d '{"name":"my-app","path":"."}'

curl -s -X POST http://127.0.0.1:8787/v1/projects/PROJECT_ID/scans \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: demo-1' \
  -d '{"mode":"balanced","enrichment":"none"}'

curl -s http://127.0.0.1:8787/v1/scans/SCAN_ID
curl -s 'http://127.0.0.1:8787/v1/findings?project_id=PROJECT_ID'
```

OpenAPI: `http://127.0.0.1:8787/openapi.json`
