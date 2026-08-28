from fastapi import Header, HTTPException
from app.config import settings

def require_api_key(x_api_key: str | None = Header(default=None)):
    if not x_api_key or x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return True
