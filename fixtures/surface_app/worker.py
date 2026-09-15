"""Background job / celery-like stub for surface inventory."""

from __future__ import annotations

from celery import Celery

celery_app = Celery("surface_app", broker="redis://localhost:6379/0")


@celery_app.task(name="surface_app.send_email")
def send_email(to: str, subject: str, body: str) -> dict:
    """Async email job — trust boundary: queue → worker."""
    return {"to": to, "subject": subject, "queued": True}


@celery_app.task(name="surface_app.sync_profile")
def sync_profile(user_id: str) -> dict:
    """Background profile sync job."""
    return {"user_id": user_id, "status": "synced"}
