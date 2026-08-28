import json
from fastapi import FastAPI, Depends
from fastapi.responses import Response
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST
from pydantic import BaseModel, Field
from app.db import SessionLocal, init_db
from app.models import Scan
from app.security import require_api_key
from app.worker import run_scan
from app.container_audit import audit_running_containers

app = FastAPI(title="ContainerGuard", version="1.0.0")
scan_requests = Counter("containerguard_scan_requests_total", "Image scan requests")

class ScanRequest(BaseModel):
    image: str = Field(min_length=1, max_length=512)

@app.on_event("startup")
def startup():
    init_db()

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.post("/api/v1/scans", dependencies=[Depends(require_api_key)])
def create_scan(req: ScanRequest):
    scan_requests.inc()
    db = SessionLocal()
    try:
        scan = Scan(image=req.image, status="queued")
        db.add(scan)
        db.commit()
        db.refresh(scan)
        run_scan.delay(scan.id, req.image)
        return {"id": scan.id, "image": scan.image, "status": scan.status}
    finally:
        db.close()

@app.get("/api/v1/scans/{scan_id}", dependencies=[Depends(require_api_key)])
def get_scan(scan_id: int):
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return {"error": "scan not found"}
        return {
            "id": scan.id, "image": scan.image, "status": scan.status,
            "result": json.loads(scan.result_json) if scan.result_json else None
        }
    finally:
        db.close()

@app.get("/api/v1/containers/security", dependencies=[Depends(require_api_key)])
def container_security():
    return {"containers": audit_running_containers()}
