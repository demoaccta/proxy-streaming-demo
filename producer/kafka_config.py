"""
Extends GeneratorConfig with Confluent Cloud connection settings.
"""
import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


@dataclass
class KafkaConfig:
    bootstrap_servers: str = field(default_factory=lambda: os.environ["KAFKA_BOOTSTRAP_SERVERS"])
    api_key: str = field(default_factory=lambda: os.environ["KAFKA_API_KEY"])
    api_secret: str = field(default_factory=lambda: os.environ["KAFKA_API_SECRET"])
    topic: str = field(default_factory=lambda: os.getenv("KAFKA_TOPIC", "wsa-proxy-logs"))

    def to_producer_config(self) -> dict:
        """confluent-kafka Producer config dict for Confluent Cloud (SASL_SSL/PLAIN)."""
        return {
            "bootstrap.servers": self.bootstrap_servers,
            "security.protocol": "SASL_SSL",
            "sasl.mechanisms": "PLAIN",
            "sasl.username": self.api_key,
            "sasl.password": self.api_secret,
            "client.id": "wsa-proxy-producer",
        }
