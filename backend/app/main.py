from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.auth_routes import router as auth_router
from app.api.chat_routes import router as chat_router
from app.api.log_routes import router as log_router
from app.api.sop_routes import router as sop_router
from app.api.ticket_routes import router as ticket_router
from app.api.alert_routes import router as alert_router
from app.routers.threat_map import router as threat_map_router, settings_router
from app.routers.notifications import router as notification_router


from app.config import settings
from app.db import SessionLocal, engine, init_db
from app.services.auth_service import seed_default_users
from app.services.embedding_service import embedding_service
from app.services.rag_engine import soc_agent
from app.services.sop_manager import sop_manager
from app.services.ticket_service import ticket_service
from app.services.vector_store import vector_store


def _seed() -> None:
    init_db()
    db = SessionLocal()
    try:
        seed_default_users(db)
        sop_manager.initialize_default_sops(db)
        ticket_service.seed_initial_tickets(db)
        vector_store.bootstrap(sop_manager.load_all_chunks(db))
    finally:
        db.close()


@asynccontextmanager
async def lifespan(_: FastAPI):
    _seed()
    embedding_service.warmup()

    provider = (settings.LLM_PROVIDER or "auto").strip().lower()
    if provider == "auto":
        if settings.OPENAI_API_KEY.strip():
            provider = "openai"
        elif settings.NVIDIA_API_KEY.strip():
            provider = "nim"
        else:
            provider = "none"
    print(f"Database engine   : {engine.url.render_as_string(hide_password=True)}")
    print(f"Vector index      : {vector_store.size} SOP chunks in FAISS")
    print(f"Embedding model   : {settings.EMBEDDING_MODEL} (loaded once per process)")
    print(f"LLM provider      : {provider}")
    if provider == "none":
        print("LLM provider      : none configured -> deterministic local synthesis")
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    description=(
        "Tool-using SOC agent for incident investigation. The agent can search "
        "approved SOP excerpts and return grounded recommendations with citations."
    ),
    version=settings.VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(chat_router, prefix=settings.API_V1_STR)
app.include_router(ticket_router, prefix=settings.API_V1_STR)
app.include_router(sop_router, prefix=settings.API_V1_STR)
app.include_router(log_router, prefix=settings.API_V1_STR)
app.include_router(threat_map_router, prefix=settings.API_V1_STR)
app.include_router(settings_router, prefix=settings.API_V1_STR)
app.include_router(alert_router, prefix=settings.API_V1_STR)
app.include_router(notification_router, prefix=settings.API_V1_STR)

app.include_router(log_router, prefix="/api")
app.include_router(auth_router, prefix="/api")
app.include_router(chat_router, prefix="/api")
app.include_router(ticket_router, prefix="/api")
app.include_router(sop_router, prefix="/api")
app.include_router(threat_map_router, prefix="/api")
app.include_router(settings_router, prefix="/api")
app.include_router(alert_router, prefix="/api")
app.include_router(notification_router, prefix="/api")




@app.get("/health", tags=["Health"])
def health() -> dict:
    return {
        "status": "ok",
        "version": settings.VERSION,
        "vector_chunks": vector_store.size,
        "llm_provider_configured": soc_agent.llm is not None,
    }
