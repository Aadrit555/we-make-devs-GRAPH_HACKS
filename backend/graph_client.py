"""
TEZCATL — Graph-Native Security Containment Agent (FalkorDB)
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""

import sys
import os

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from graph_client import (
    FalkorGraphClient,
    ReadOnlyGraphClient,
    validate_node_id,
    DatabaseConnectionError,
    GraphQueryError,
    EvidenceUnavailableError,
)

__all__ = [
    "FalkorGraphClient",
    "ReadOnlyGraphClient",
    "validate_node_id",
    "DatabaseConnectionError",
    "GraphQueryError",
    "EvidenceUnavailableError",
]
