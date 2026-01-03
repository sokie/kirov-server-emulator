import os

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, JsonConfigSettingsSource, SettingsConfigDict

from app.util.paths import get_runtime_path


class IRCSettings(BaseModel):
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=6667, gt=1024, lt=65536)
    server_name: str = Field(default="peerchat.ea.com")


class GameSettings(BaseModel):
    """Game-specific settings."""

    gamekey: str = Field()


class LoggingSettings(BaseModel):
    """Logging configuration."""

    level: str = Field(default="INFO", description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)")


class FeslSettings(BaseModel):
    """FESL (EA Frontend Server Layer) settings."""

    host: str = Field(default="0.0.0.0")
    port: int = Field(default=18800, gt=1024, lt=65536)


class GpSettings(BaseModel):
    """GameSpy Presence server settings."""

    host: str = Field(default="0.0.0.0")
    port: int = Field(default=29900, gt=1024, lt=65536)


class NatNegSettings(BaseModel):
    """NAT Negotiation server settings."""

    host: str = Field(default="0.0.0.0")
    port: int = Field(default=27901, gt=1024, lt=65536)
    session_timeout: int = Field(default=30)  # Seconds to wait for both clients
    enabled: bool = Field(default=True)
    force_lan_mode: bool = Field(
        default=True, description="Always use LAN mode (local IPs). WAN mode (NAT punchthrough) is experimental."
    )


class MasterServerSettings(BaseModel):
    """GameSpy Master Server settings for server/room list queries."""

    host: str = Field(default="0.0.0.0")
    port: int = Field(default=28910, gt=1024, lt=65536)  # TCP port for queries
    udp_port: int = Field(default=27900, gt=1024, lt=65536)  # UDP port for heartbeats
    enabled: bool = Field(default=True)


# Compute config path at module load time for frozen executable support
_config_path = os.path.join(get_runtime_path(), "config.json")


class AppSettings(BaseSettings):
    irc: IRCSettings = Field(default_factory=IRCSettings)
    fesl: FeslSettings = Field(default_factory=FeslSettings)
    gp: GpSettings = Field(default_factory=GpSettings)
    natneg: NatNegSettings = Field(default_factory=NatNegSettings)
    master: MasterServerSettings = Field(default_factory=MasterServerSettings)
    game: GameSettings = Field()
    logging: LoggingSettings = Field(default_factory=LoggingSettings)

    model_config = SettingsConfigDict(
        json_file=_config_path,
        json_file_encoding="utf-8",
        extra="ignore",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        return (
            JsonConfigSettingsSource(settings_cls),
            env_settings,
            init_settings,
            dotenv_settings,
            file_secret_settings,
        )


app_config = AppSettings()
