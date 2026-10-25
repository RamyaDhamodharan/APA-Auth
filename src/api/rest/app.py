from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.rest.routes import auth_routes, health_routes, users_routes
from src.core.config_core import get_settings

app = FastAPI(
    title="GenWorx AP Auth Service",
    version="0.1.0",
    description="Authentication service for GenWorx AP Assistant",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in get_settings().cors_allowed_origins.split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Protection"],
)
app.include_router(health_routes.router)
app.include_router(auth_routes.router)
app.include_router(auth_routes.password_change_alias_router)
app.include_router(users_routes.router)
app.include_router(users_routes.admin_associates_router)


@app.get("/")
def root() -> dict[str, str]:
    return {
        "service": "genworx-ap-auth",
        "status": "running",
    }
