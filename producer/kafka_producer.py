"""
Streams synthetic Cisco WSA proxy events into a Confluent Cloud Kafka topic.
Run this instead of local_test.py once Confluent Cloud is wired up (Phase 3).
"""
import json
import time
import sys

from confluent_kafka import Producer

from config import GeneratorConfig
from generator import ProxyLogGenerator
from kafka_config import KafkaConfig


def delivery_report(err, msg):
    if err is not None:
        print(f"  !! DELIVERY FAILED: {err}", file=sys.stderr)
    # Successful deliveries are intentionally silent to keep console output readable
    # at higher events/sec - the label line below is the primary feedback.


def main():
    gen_cfg = GeneratorConfig()
    kafka_cfg = KafkaConfig()
    gen = ProxyLogGenerator(gen_cfg)

    producer = Producer(kafka_cfg.to_producer_config())

    print(f"Streaming synthetic Cisco WSA proxy events to Kafka topic "
          f"'{kafka_cfg.topic}' ({gen_cfg.events_per_second}/sec, "
          f"{gen_cfg.bad_event_percentage}% bad)...\n")

    delay = 1.0 / gen_cfg.events_per_second if gen_cfg.events_per_second > 0 else 0
    count = 0
    good_count = 0
    bad_count = 0

    try:
        while True:
            event = gen.generate_one()
            is_bad = gen.is_bad(event)
            label = "BAD " if is_bad else "GOOD"
            print(f"{label}  {event['http_method']:6s} {event['destination_host']:35s} {event['http_status']}")

            producer.produce(
                kafka_cfg.topic,
                key=event["source_ip"],
                value=json.dumps(event),
                callback=delivery_report,
            )
            producer.poll(0)  # trigger delivery callbacks without blocking

            count += 1
            bad_count += 1 if is_bad else 0
            good_count += 0 if is_bad else 1

            if delay:
                time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n\nFlushing remaining messages...")
        producer.flush(timeout=10)
        print(f"Stopped. Sent {count} events to Kafka: {good_count} good, {bad_count} bad "
              f"({bad_count / count * 100:.1f}% bad).")


if __name__ == "__main__":
    main()
