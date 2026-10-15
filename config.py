"""
config.py — Typed application configuration for CUTLINE v2 using pydantic-settings.

Enforces zero-hardcoding environment configuration with strict validation.
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central typed settings for database connections, graph defaults, and external services."""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    falkordb_host: str = Field(default="127.0.0.1", alias="FALKORDB_HOST")
    falkordb_port: int = Field(default=6379, alias="FALKORDB_PORT")
    falkordb_graph: str = Field(default="cutline_demo", alias="FALKORDB_GRAPH")
    cutline_source_id: str = Field(default="ci_runner", alias="CUTLINE_SOURCE_ID")
    cutline_target_id: str = Field(default="signing_key", alias="CUTLINE_TARGET_ID")
    cutline_max_hops: int = Field(default=8, alias="CUTLINE_MAX_HOPS")
    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4o-mini", alias="OPENAI_MODEL")


settings = Settings()
