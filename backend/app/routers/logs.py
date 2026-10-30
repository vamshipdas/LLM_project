"""
Router re-export to satisfy both `app.routers.logs` and `app.api.log_routes`.
"""
from app.api.log_routes import router

__all__ = ["router"]
