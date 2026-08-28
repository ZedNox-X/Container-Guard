import json
from celery import Celery
from app.config import settings
from app.db import SessionLocal
from app.models import Scan
from app.scanner import scan_image

celery_app = Celery("containerguard", broker=settings.redis_url, backend=settings.redis_url)

@celery_app.task(bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
def run_scan(self, scan_id: int, image: str):
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return
        scan.status = "running"
        db.commit()
        result = scan_image(image)
        scan.status = result.get("status", "error")
        scan.result_json = json.dumps(result)
        db.commit()
        return result
    finally:
        db.close()
