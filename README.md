# ContainerGuard

Enterprise Docker security platform for Docker image vulnerability scanning and running-container security checks.

## V1 Features

- Trivy-based Docker/OCI image vulnerability scanning
- Running-container configuration auditing through the Docker Engine API
- Security severity thresholds and policy evaluation
- FastAPI REST API
- PostgreSQL persistence
- Redis + Celery background scans
- API key authentication
- Prometheus metrics
- Docker Compose development stack
- Pytest test suite
- GitHub Actions CI and security workflows
  
- <img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/913a29ac-71fb-41d0-be57-859487b313cd" />

## Quick start
Requirements: Docker Engine with Compose v2.
```bash
cp .env.example .env
docker compose up --build
```
API: http://localhost:8000
Docs: http://localhost:8000/docs
Metrics: http://localhost:8000/metrics

Scan an image:

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "X-API-Key: change-me-in-production" \
  -H "Content-Type: application/json" \
  -d '{"image":"alpine:3.20"}'
```

List running-container findings:

```bash
curl http://localhost:8000/api/v1/containers/security \
  -H "X-API-Key: change-me-in-production"
```

## Security model

ContainerGuard is a defensive auditing tool. It does not modify containers, pull arbitrary code, or attempt exploitation. The scanner uses Trivy for image CVEs and Docker Engine metadata for configuration checks.

For production, run the API behind TLS, use a dedicated read-only Docker socket proxy, rotate API credentials, restrict network access, and pin image versions.
- Version: 001
