"""
config.py — Central typed application configuration for TEZCATL using pydantic-settings.

Enforces zero-hardcoding environment configuration with strict validation.
"""

from pydantic import Field, AliasChoices
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central typed settings for TEZCATL database connections, graph defaults, and external services."""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    falkordb_host: str = Field(default="127.0.0.1", alias="FALKORDB_HOST")
    falkordb_port: int = Field(default=6379, alias="FALKORDB_PORT")
    falkordb_graph: str = Field(
        default="prod_graph",
        validation_alias=AliasChoices("TEZCATL_PROD_GRAPH", "FALKORDB_GRAPH")
    )
    falkordb_mirror_graph: str = Field(
        default="tezcatl_mirror",
        validation_alias=AliasChoices("TEZCATL_MIRROR_GRAPH", "FALKORDB_MIRROR_GRAPH")
    )
    tezcatl_source_id: str = Field(default="ci_runner", alias="TEZCATL_SOURCE_ID")
    tezcatl_target_id: str = Field(default="signing_key", alias="TEZCATL_TARGET_ID")
    tezcatl_max_hops: int = Field(default=8, alias="TEZCATL_MAX_HOPS")
    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4o-mini", alias="OPENAI_MODEL")


settings = Settings()
