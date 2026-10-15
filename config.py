"""
config.py — Typed application configuration for TEZCATL using pydantic-settings.

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
        validation_alias=AliasChoices("TEZCATL_PROD_GRAPH", "FALKORDB_GRAPH", "CUTLINE_GRAPH")
    )
    falkordb_mirror_graph: str = Field(
        default="tezcatl_mirror",
        validation_alias=AliasChoices("TEZCATL_MIRROR_GRAPH", "FALKORDB_MIRROR_GRAPH")
    )
    tezcatl_source_id: str = Field(
        default="ci_runner",
        validation_alias=AliasChoices("TEZCATL_SOURCE_ID", "CUTLINE_SOURCE_ID")
    )
    tezcatl_target_id: str = Field(
        default="signing_key",
        validation_alias=AliasChoices("TEZCATL_TARGET_ID", "CUTLINE_TARGET_ID")
    )
    tezcatl_max_hops: int = Field(
        default=8,
        validation_alias=AliasChoices("TEZCATL_MAX_HOPS", "CUTLINE_MAX_HOPS")
    )
    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4o-mini", alias="OPENAI_MODEL")

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
