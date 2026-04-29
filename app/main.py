"""
POC-03: Zero-Trust AI Gateway
PII & Secrets masking middleware proxy for external LLM APIs.
"""
from contextlib import asynccontextmanager
import time, uuid, sys

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger

from app.core.config import settings
from app.core.exceptions import GatewayException, MaskingPolicyViolation, UpstreamLLMException, ValidationException
from app.core.database import init_db
from app.api.routes import gateway_router


def setup_logging():
    logger.remove()
    logger.add(sys.stdout, format="<cyan>{time}</cyan> | <level>{level:<8}</level> | {name}:{function} - {message}", level="INFO", colorize=True)
    logger.add("logs/zt_gateway_{time}.log", rotation="100 MB", retention="30 days", level="DEBUG", serialize=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    logger.info("Zero-Trust AI Gateway starting up")
    await init_db()
    logger.info("Gateway ready.")
    yield
    logger.info("Zero-Trust AI Gateway shut down")


app = FastAPI(
    title="Zero-Trust AI Gateway",
    description="PII & Secrets masking middleware proxy for external LLM APIs. Uses Regex + spaCy NER to detect and mask sensitive data before any prompt reaches an external model.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(CORSMiddleware, allow_origins=settings.ALLOWED_ORIGINS, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


@app.middleware("http")
async def audit_logging_middleware(request: Request, call_next):
    start = time.time()
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"[GATEWAY] {request.method} {request.url.path} | req_id={request_id[:8]} ip={client_ip}")
    response = await call_next(request)
    duration_ms = round((time.time() - start) * 1000, 2)
    logger.info(f"[GATEWAY] {response.status_code} | req_id={request_id[:8]} ms={duration_ms}")
    response.headers["X-Request-Duration-Ms"] = str(duration_ms)
    return response


@app.exception_handler(MaskingPolicyViolation)
async def policy_violation_handler(request: Request, exc: MaskingPolicyViolation):
    logger.warning(f"[POLICY BLOCK] path={request.url.path} critical_types={exc.critical_types}")
    return JSONResponse(status_code=400, content={"error": exc.detail, "code": exc.error_code, "critical_pii_types": exc.critical_types})

@app.exception_handler(UpstreamLLMException)
async def upstream_llm_handler(request: Request, exc: UpstreamLLMException):
    logger.error(f"Upstream LLM error: {exc.detail}")
    return JSONResponse(status_code=503, content={"error": exc.detail, "code": exc.error_code})

@app.exception_handler(ValidationException)
async def validation_handler(request: Request, exc: ValidationException):
    return JSONResponse(status_code=422, content={"error": exc.detail, "code": exc.error_code, "fields": exc.fields})

@app.exception_handler(GatewayException)
async def gateway_handler(request: Request, exc: GatewayException):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail, "code": exc.error_code})

@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception):
    logger.critical(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"error": "Internal server error", "code": "INTERNAL_ERROR"})


app.include_router(gateway_router, prefix="/api/v1/gateway", tags=["Zero-Trust Gateway"])


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy", "service": "zero-trust-ai-gateway", "version": "1.0.0"}
