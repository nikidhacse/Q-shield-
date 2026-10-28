"""
Q-Shield FastAPI application entry point.

Sets up:
- FastAPI app with OpenAPI metadata
- CORS middleware
- Structured logging
- All API routers
- Health check endpoint
"""

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("qshield")


# ---------------------------------------------------------------------------
# Lifespan handler (startup / shutdown hooks)
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} [{settings.APP_ENV}]")
    yield
    logger.info("Q-Shield backend shutting down.")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Q-Shield – Quantum-Risk Cryptographic Auditing API",
    description=(
        "Q-Shield helps organizations identify cryptographic technologies in their infrastructure, "
        "assess quantum migration risk, prioritize assets for migration, and generate actionable "
        "recommendations. This API is the backend for the Q-Shield platform.\n\n"
        "**Important:** Q-Shield does NOT perform destructive testing, password cracking, "
        "exploitation, or unauthorized network attacks."
    ),
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
    contact={
        "name": "Q-Shield Security Team",
        "email": "security@qshield.example.com",
    },
    license_info={
        "name": "Proprietary",
    },
)

# ---------------------------------------------------------------------------
# CORS middleware
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Register routers
# ---------------------------------------------------------------------------
from app.api.routes import auth, assets, scans, crypto, risk, migration, reports, dashboard  # noqa: E402

API_PREFIX = settings.API_PREFIX

app.include_router(auth.router, prefix=API_PREFIX)
app.include_router(assets.router, prefix=API_PREFIX)
app.include_router(scans.router, prefix=API_PREFIX)
app.include_router(crypto.router, prefix=API_PREFIX)
app.include_router(risk.router, prefix=API_PREFIX)
app.include_router(migration.router, prefix=API_PREFIX)
app.include_router(reports.router, prefix=API_PREFIX)
app.include_router(dashboard.router, prefix=API_PREFIX)


# ---------------------------------------------------------------------------
# Health check endpoint
# ---------------------------------------------------------------------------
@app.get("/health", tags=["Health"], summary="Service health check")
def health_check():
    """
    Returns a simple alive response.
    Used by load balancers and container orchestrators.
    """
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV,
    }


@app.get("/", tags=["Root"])
def root():
    """API root – points to documentation."""
    return {
        "message": f"Welcome to {settings.APP_NAME} API",
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "health": "/health",
    }
