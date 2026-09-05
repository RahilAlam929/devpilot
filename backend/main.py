from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.projects import router as projects_router
from app.api.repositories import router as repositories_router
from app.api.scans import router as scans_router
from app.api.users import router as users_router


app = FastAPI(
    title="DevPilot API",
    version="0.1.0",
    description="AI-native developer platform API",
)



app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "devpilot-api",
        "version": "0.1.0",
    }


app.include_router(users_router, prefix="/api")
app.include_router(projects_router, prefix="/api")
app.include_router(repositories_router, prefix="/api")
app.include_router(scans_router, prefix="/api")
