"""
TEZCATL Sovereign Graph Engine — Authored by Aadrit555
config.py — Central configuration for FalkorDB connections and graph topology defaults.

Zero external API dependencies. Pure first-party architecture.
"""

import os
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration for local and containerized FalkorDB graph instances."""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    falkordb_host: str = Field(default="127.0.0.1", alias="FALKORDB_HOST")
    falkordb_port: int = Field(default=6379, alias="FALKORDB_PORT")
    falkordb_graph: str = Field(default="prod_graph", alias="FALKORDB_GRAPH")
    falkordb_mirror_graph: str = Field(default="tezcatl_mirror", alias="TEZCATL_MIRROR_GRAPH")
    tezcatl_source_id: str = Field(default="ci_runner", alias="TEZCATL_SOURCE_ID")
    tezcatl_target_id: str = Field(default="signing_key", alias="TEZCATL_TARGET_ID")
    tezcatl_max_hops: int = Field(default=8, alias="TEZCATL_MAX_HOPS")


settings = Settings()
