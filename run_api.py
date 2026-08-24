"""Local launcher for the Healthcare CTI FastAPI application."""

print("Loading Healthcare CTI API...", flush=True)
from main import app

print("Starting Healthcare CTI API on http://127.0.0.1:8000", flush=True)
import uvicorn


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000, lifespan="on")
