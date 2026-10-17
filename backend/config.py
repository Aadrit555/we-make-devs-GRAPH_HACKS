"""
TEZCATL — Graph-Native Breach Containment Agent on FalkorDB
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""
import os

FALKORDB_HOST = os.getenv("FALKORDB_HOST", "localhost")
FALKORDB_PORT = int(os.getenv("FALKORDB_PORT", "6379"))
PROD_GRAPH = os.getenv("TEZCATL_PROD_GRAPH", "prod_graph")
MIRROR_GRAPH = os.getenv("TEZCATL_MIRROR_GRAPH", "tezcatl_mirror")

ADMIN_TOKEN = os.getenv("TEZCATL_ADMIN_TOKEN", "tezcatl-demo-auth-2026")
REQUIRE_AUTH = os.getenv("TEZCATL_REQUIRE_AUTH", "true").lower() in ("1", "true", "yes")
DB_STARTUP_RETRIES = int(os.getenv("DB_STARTUP_RETRIES", "5"))
DB_RETRY_INTERVAL = float(os.getenv("DB_RETRY_INTERVAL", "1.5"))

