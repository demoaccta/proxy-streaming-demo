"""
Streams synthetic Cisco WSA proxy events to Confluent Cloud via the Kafka
REST Produce API (HTTPS/443) instead of the native Kafka protocol (9092).

Use this instead of kafka_producer.py on networks that block port 9092
but allow standard HTTPS - e.g. locked-down corporate/AVD environments.
Functionally equivalent: same cluster, same topic, same event bytes.
"""
import base64
import json
import os
import sys
import time

import requests
from dotenv import load_dotenv

from config import GeneratorConfig
from generator import ProxyLogGenerator

load_dotenv()

REST_ENDPOINT = os.environ["KAFKA_REST_ENDPOINT"].rstrip("/")
CLUSTER_ID = os.environ["KAFKA_CLUSTER_ID"]
API_KEY = os.environ["KAFKA_API_KEY"]
API_SECRET = os.environ["KAFKA_API_SECRET"]
TOPIC = os.getenv("KAFKA_TOPIC", "wsa-proxy-logs")

PRODUCE_URL = f"{REST_ENDPOINT}/kafka/v3/clusters/{CLUSTER_ID}/topics/{TOPIC}/records"

_auth_bytes = f"{API_KEY}:{API_SECRET}".encode("utf-8")
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": f"Basic {base64.b64encode(_auth_bytes).decode('ascii')}",
}


def send_event(event: dict, session: requests.Session) -> bool:
    """Returns True on success, False on failure (prints the error either way)."""
    body = {
        "key": {"type": "STRING", "data": event["source_ip"]},
        "value": {"type": "STRING", "data": json.dumps(event)},
    }
    try:
        resp = session.post(PRODUCE_URL, headers=HEADERS, json=body, timeout=10)
        if resp.status_code == 200:
            return True
        print(f"  !! DELIVERY FAILED ({resp.status_code}): {resp.text[:200]}", file=sys.stderr)
        return False
    except requests.exceptions.RequestException as exc:
        print(f"  !! REQUEST ERROR: {exc}", file=sys.stderr)
        return False


def main():
    gen_cfg = GeneratorConfig()
    gen = ProxyLogGenerator(gen_cfg)
    session = requests.Session()  # reuses the HTTPS connection across requests

    print(f"Streaming synthetic Cisco WSA proxy events to Kafka topic "
          f"'{TOPIC}' via REST API ({gen_cfg.events_per_second}/sec, "
          f"{gen_cfg.bad_event_percentage}% bad)...\n")

    delay = 1.0 / gen_cfg.events_per_second if gen_cfg.events_per_second > 0 else 0
    count = 0
    good_count = 0
    bad_count = 0
    failed_count = 0

    try:
        while True:
            event = gen.generate_one()
            is_bad = gen.is_bad(event)
            label = "BAD " if is_bad else "GOOD"
            print(f"{label}  {event['http_method']:6s} {event['destination_host']:35s} {event['http_status']}")

            ok = send_event(event, session)

            count += 1
            if not ok:
                failed_count += 1
            bad_count += 1 if is_bad else 0
            good_count += 0 if is_bad else 1

            if delay:
                time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n\nStopped. Sent {count} events: {good_count} good, {bad_count} bad "
              f"({bad_count / count * 100:.1f}% bad), {failed_count} delivery failures.")


if __name__ == "__main__":
    main()
