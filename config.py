"""
config.py — Typed application configuration for TEZCATL.

Enforces zero-hardcoding environment configuration with strict validation.
Zero external API keys: 100% self-contained sovereign execution.
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
    tezcatl_source_id: str = Field(default_factory=lambda: os.getenv("TEZCATL_SOURCE_ID", "ci_runner"))
    tezcatl_target_id: str = Field(default_factory=lambda: os.getenv("TEZCATL_TARGET_ID", "signing_key"))
    tezcatl_max_hops: int = Field(default_factory=lambda: int(os.getenv("TEZCATL_MAX_HOPS", "8")))

    # Backward compatibility properties
    @property
    def cutline_source_id(self) -> str:
        return self.tezcatl_source_id

    @property
    def cutline_target_id(self) -> str:
        return self.tezcatl_target_id

    @property
    def cutline_max_hops(self) -> int:
        return self.tezcatl_max_hops


settings = Settings()
