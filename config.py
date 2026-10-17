"""
TEZCATL — Graph-Native Security Containment Agent (FalkorDB)
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""

import os
from pydantic import BaseModel, Field


class Settings(BaseModel):
    """Central typed settings for TEZCATL database connections and graph defaults."""

    falkordb_host: str = Field(default_factory=lambda: os.getenv("FALKORDB_HOST", "127.0.0.1"))
    falkordb_port: int = Field(default_factory=lambda: int(os.getenv("FALKORDB_PORT", "6379")))
    falkordb_graph: str = Field(
        default_factory=lambda: os.getenv("TEZCATL_PROD_GRAPH", os.getenv("FALKORDB_GRAPH", "prod_graph"))
    )
    falkordb_mirror_graph: str = Field(
        default_factory=lambda: os.getenv("TEZCATL_MIRROR_GRAPH", os.getenv("FALKORDB_MIRROR_GRAPH", "tezcatl_mirror"))
    )
    tezcatl_source_id: str = Field(default_factory=lambda: os.getenv("TEZCATL_SOURCE_ID", "ci-runner-07"))
    tezcatl_target_id: str = Field(default_factory=lambda: os.getenv("TEZCATL_TARGET_ID", "prod-signing-key"))
    tezcatl_max_hops: int = Field(default_factory=lambda: int(os.getenv("TEZCATL_MAX_HOPS", "8")))

    @property
    def default_source_id(self) -> str:
        return self.tezcatl_source_id

    @property
    def default_target_id(self) -> str:
        return self.tezcatl_target_id

    @property
    def default_max_hops(self) -> int:
        return self.tezcatl_max_hops


settings = Settings()
