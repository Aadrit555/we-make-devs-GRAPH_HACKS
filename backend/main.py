"""
TEZCATL — Graph-Native Security Containment Agent (FalkorDB)
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""

import sys
import os

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app import app

__all__ = ["app"]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
