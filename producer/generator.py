"""
Synthetic Cisco WSA-style proxy log generator.

Produces a stream of JSON events shaped like a normalized Cisco WSA proxy
log, with a configurable mix of normal ("good") and security-relevant
("bad") traffic. Safe synthetic indicators only - no real exploit payloads.
"""
import random
import uuid
from datetime import datetime, timezone

from faker import Faker
from config import GeneratorConfig

fake = Faker()

# --- Fixed pools, generated once per process so entities recur realistically ---

def _build_pools(cfg: GeneratorConfig):
    return {
        "users": [fake.user_name() for _ in range(cfg.num_users)],
        "source_ips": [fake.ipv4_private() for _ in range(cfg.num_source_ips)],
        "good_domains": [fake.domain_name() for _ in range(cfg.num_good_domains)],
        # Bad domains look deliberately sketchy - safe, made-up patterns only
        "bad_domains": [
            f"{fake.word()}-{fake.word()}-verify.{fake.tld()}" for _ in range(cfg.num_bad_domains)
        ],
    }


GOOD_STATUS_CODES = [200, 200, 200, 200, 301, 304]
GOOD_METHODS = ["GET", "GET", "GET", "POST"]
GOOD_PATHS = ["/", "/index.html", "/api/status", "/products", "/search", "/images/logo.png"]
GOOD_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/605.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/124.0",
]
GOOD_CATEGORIES = ["Business", "News", "Search Engines", "Software Updates", "Reference"]

# Each "bad" template carries everything needed to build the event consistently
BAD_EVENT_TEMPLATES = [
    {
        "event_type": "POLICY_VIOLATION",
        "http_status": 403,
        "action": "BLOCK",
        "category": "Malware",
        "severity": "HIGH",
        "reason": "blocked category: malware-associated domain",
        "path": "/",
        "method": "GET",
    },
    {
        "event_type": "POLICY_VIOLATION",
        "http_status": 403,
        "action": "BLOCK",
        "category": "Phishing",
        "severity": "HIGH",
        "reason": "blocked category: phishing",
        "path": "/login/verify-account",
        "method": "POST",
    },
    {
        "event_type": "AUTH_FAILURE",
        "http_status": 401,
        "action": "BLOCK",
        "category": "Uncategorized",
        "severity": "MEDIUM",
        "reason": "authentication failed: invalid proxy credentials",
        "path": "/",
        "method": "GET",
    },
    {
        "event_type": "SUSPICIOUS_REQUEST",
        "http_status": 404,
        "action": "ALLOW",
        "category": "Uncategorized",
        "severity": "MEDIUM",
        "reason": "suspicious path pattern: possible traversal attempt",
        "path": "/../../etc/passwd",
        "method": "GET",
    },
    {
        "event_type": "SUSPICIOUS_REQUEST",
        "http_status": 400,
        "action": "BLOCK",
        "category": "Uncategorized",
        "severity": "MEDIUM",
        "reason": "unusual HTTP method for destination",
        "path": "/admin/config",
        "method": "TRACE",
    },
    {
        "event_type": "MALWARE_DETECTED",
        "http_status": 403,
        "action": "BLOCK",
        "category": "Malware",
        "severity": "CRITICAL",
        "reason": "malware signature match on response payload",
        "path": "/download/setup.exe",
        "method": "GET",
    },
    {
        "event_type": "SUSPICIOUS_REQUEST",
        "http_status": 404,
        "action": "ALLOW",
        "category": "Uncategorized",
        "severity": "LOW",
        "reason": "suspicious path pattern: possible injection probe",
        "path": "/search?q=%27--",
        "method": "GET",
    },
    {
        "event_type": "SERVER_ERROR",
        "http_status": 500,
        "action": "ALLOW",
        "category": "Business",
        "severity": "LOW",
        "reason": "upstream server error",
        "path": "/api/orders",
        "method": "POST",
    },
]


def _make_good_event(cfg: GeneratorConfig, pools: dict) -> dict:
    domain = random.choice(pools["good_domains"])
    bytes_sent = random.randint(200, 2000)
    bytes_received = random.randint(1000, 500000)
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": random.choice(pools["source_ips"]),
        "username": random.choice(pools["users"]),
        "destination_host": domain,
        "url": f"https://{domain}{random.choice(GOOD_PATHS)}",
        "http_method": random.choice(GOOD_METHODS),
        "http_status": random.choice(GOOD_STATUS_CODES),
        "user_agent": random.choice(GOOD_USER_AGENTS),
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "action": "ALLOW",
        "category": random.choice(GOOD_CATEGORIES),
        "severity": "INFO",
        "reason": None,
        "event_type": "NORMAL_REQUEST",
    }


def _make_bad_event(cfg: GeneratorConfig, pools: dict) -> dict:
    template = random.choice(BAD_EVENT_TEMPLATES)
    domain = random.choice(pools["bad_domains"])
    bytes_sent = random.randint(100, 800)
    bytes_received = random.randint(0, 5000)  # blocked requests often return little/no body
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": random.choice(pools["source_ips"]),
        "username": random.choice(pools["users"]),
        "destination_host": domain,
        "url": f"https://{domain}{template['path']}",
        "http_method": template["method"],
        "http_status": template["http_status"],
        "user_agent": random.choice(GOOD_USER_AGENTS),  # attacker traffic often uses normal UAs
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "action": template["action"],
        "category": template["category"],
        "severity": template["severity"],
        "reason": template["reason"],
        "event_type": template["event_type"],
    }


class ProxyLogGenerator:
    """Stateful generator: builds entity pools once, then yields events on demand."""

    def __init__(self, cfg: GeneratorConfig | None = None):
        self.cfg = cfg or GeneratorConfig()
        self.pools = _build_pools(self.cfg)

    def generate_one(self, bad_event_percentage: float | None = None) -> dict:
        pct = self.cfg.bad_event_percentage if bad_event_percentage is None else bad_event_percentage
        is_bad = random.uniform(0, 100) < pct
        return _make_bad_event(self.cfg, self.pools) if is_bad else _make_good_event(self.cfg, self.pools)

    def is_bad(self, event: dict) -> bool:
        return event["action"] == "BLOCK" or event["severity"] in ("MEDIUM", "HIGH", "CRITICAL") or event["http_status"] >= 400
