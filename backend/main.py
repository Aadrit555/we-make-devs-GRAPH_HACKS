"""
backend/main.py — Entry point wrapper for TEZCATL FastAPI Gateway.
Exposes 'app' from root app.py for backend/main:app compatibility.
"""

import sys
import os

# Ensure root directory is in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app import app

__all__ = ["app"]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)

