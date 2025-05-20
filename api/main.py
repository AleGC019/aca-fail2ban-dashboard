import os  # Para construir rutas de directorios
from datetime import datetime  # Para el año en el footer
from fastapi import FastAPI, Request  # 'Request' es necesario para las plantillas
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles  # Para servir CSS, JS, imágenes
from fastapi.templating import Jinja2Templates  # Para renderizar HTML
from fastapi.responses import HTMLResponse  # Para el tipo de respuesta

# Tus importaciones existentes
from controllers import logs, jails
from configuration.settings import load_env_or_fail

# Carga variables de entorno y valida LOKI_QUERY_URL
load_env_or_fail()

# --- Define la ruta base del directorio de la API ---
# __file__ se refiere a este archivo (main.py)
# os.path.dirname(__file__) es el directorio donde está main.py (es decir, 'api/')
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = FastAPI(
    title="Fail2ban Log API",
    description="API para consultar logs de Fail2ban y gestionar baneos.",
    version="1.0.0"
    # Las rutas por defecto para /docs y /redoc ya están habilitadas
)

# --- Configuración de CORS (la que ya tenías) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # En producción, restringir
    allow_credentials=True,
    allow_methods=["GET", "POST"], # Puedes añadir más si los usas
    allow_headers=["*"], # En producción, restringir
)

# --- Montar directorio estático para CSS ---
# Esto le dice a FastAPI: "Cualquier solicitud que comience con '/static'..."
# "...debe servirse desde el directorio 'static' que está dentro de BASE_DIR (tu carpeta 'api/static/')"
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

# --- Configurar plantillas Jinja2 ---
# Esto le dice a FastAPI: "Busca mis plantillas HTML en el directorio 'templates'..."
# "...que está dentro de BASE_DIR (tu carpeta 'api/templates/')"
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# --- Ruta Raíz para servir el HTML de inicio ---
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def read_root(request: Request):
    """
    Página de inicio de la API que dirige a la documentación.
    """
    # Renderiza 'index.html' desde el directorio 'templates'
    # y le pasa las variables 'project_name' y 'current_year'
    return templates.TemplateResponse("index.html", {
        "request": request, # Obligatorio para Jinja2Templates
        "project_name": "API de Monitoreo Fail2ban",
        "current_year": datetime.utcnow().year
    })

# --- Tus Routers Existentes ---
# Los incluyes como ya lo hacías.
app.include_router(logs.router, prefix="", tags=["Endpoints de Logs y Sistema"])
app.include_router(jails.router, prefix="", tags=["Endpoints de Gestión de Jails"])
# Asegúrate de que los paths dentro de logs.router y jails.router no creen conflictos
# con la ruta raíz "/". Por ejemplo, si logs.router tiene una ruta "/", eso sería un problema.
# Pero si tiene "/health", "/fail2ban-logs", etc., está perfecto con prefix="".
