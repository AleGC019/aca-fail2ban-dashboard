from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from controllers import logs, jails
from configuration.settings import load_env_or_fail, router as settings_router

# Carga variables de entorno y valida LOKI_QUERY_URL
load_env_or_fail()

app = FastAPI(
    title="Fail2ban Log API",
    description="API para consultar logs de Fail2ban y gestionar baneos.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Rutas
app.include_router(logs.router, prefix="")
app.include_router(jails.router, prefix="")
app.include_router(settings_router, prefix="")
