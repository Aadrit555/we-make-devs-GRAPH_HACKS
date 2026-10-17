"""
TEZCATL — Graph-Native Breach Containment Agent on FalkorDB
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""
import os

FALKORDB_HOST = os.getenv("FALKORDB_HOST", "localhost")
FALKORDB_PORT = int(os.getenv("FALKORDB_PORT", "6379"))
PROD_GRAPH = os.getenv("TEZCATL_PROD_GRAPH", "prod_graph")
MIRROR_GRAPH = os.getenv("TEZCATL_MIRROR_GRAPH", "tezcatl_mirror")

# Topology Manifest & Analysis Limits
MAX_MANIFEST_BYTES = 1_048_576  # 1 MB
MAX_NODE_COUNT = 250
MAX_EDGE_COUNT = 500
MAX_TRAVERSAL_DEPTH = 8
MAX_CANDIDATES = 100

