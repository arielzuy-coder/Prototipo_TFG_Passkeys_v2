"""
Prototipo de autenticación corporativa: Passkeys (FIDO2/WebAuthn) + Zero Trust + autenticación adaptativa.

Este módulo solo arma la aplicación; los endpoints están en routers/.
"""
import logging

from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from audit_reports import router as audit_reports_router
from config import settings
from database import get_db
from routers.admin_routes import router as admin_router
from routers.auth_routes import router as auth_router
from routers.me_routes import router as me_router
from routers.monitoring_routes import router as monitoring_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Prototipo Autenticación Passkeys + Zero Trust",
    description="Sistema de autenticación passwordless con evaluación de riesgo contextual",
    version="2.0.0",
)

# CORS: solo orígenes explícitos (ORIGIN + CORS_ORIGINS). Sin comodines ni regex.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,  # la API usa Bearer tokens, no cookies
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


app.include_router(auth_router)
app.include_router(me_router)
app.include_router(admin_router)
app.include_router(monitoring_router)
app.include_router(audit_reports_router)


@app.get("/")
def root():
    return {"message": "Prototipo Autenticación Passkeys + Zero Trust", "version": app.version, "status": "running"}


@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        logger.error("Health check failed: %s", e)
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            content={"status": "unhealthy", "database": "unavailable"})


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception on %s %s", request.method, request.url.path, exc_info=True)
    return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        content={"detail": "Error interno del servidor"})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
