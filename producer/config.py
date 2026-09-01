"""
Configuration for the synthetic Cisco WSA proxy-log generator.
All values are overridable via environment variables (see .env.example).
"""
import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


def _env_int(name: str, default: int) -> int:
    return int(os.getenv(name, default))


def _env_float(name: str, default: float) -> float:
    return float(os.getenv(name, default))


@dataclass
class GeneratorConfig:
    # Volume / mix
    events_per_second: float = field(default_factory=lambda: _env_float("EVENTS_PER_SECOND", 5))
    bad_event_percentage: float = field(default_factory=lambda: _env_float("BAD_EVENT_PERCENTAGE", 5))

    # Cardinality of synthetic entities
    num_users: int = field(default_factory=lambda: _env_int("NUM_USERS", 25))
    num_source_ips: int = field(default_factory=lambda: _env_int("NUM_SOURCE_IPS", 30))
    num_good_domains: int = field(default_factory=lambda: _env_int("NUM_GOOD_DOMAINS", 15))
    num_bad_domains: int = field(default_factory=lambda: _env_int("NUM_BAD_DOMAINS", 8))

    @property
    def good_event_percentage(self) -> float:
        return 100 - self.bad_event_percentage
