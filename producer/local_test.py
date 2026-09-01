"""
Local, Kafka-free test of the synthetic proxy-log generator.
Run this to eyeball the event mix and shape before we wire in Kafka (Phase 5).
"""
import argparse
import json
import sys
import time

from config import GeneratorConfig
from generator import ProxyLogGenerator


def effective_bad_event_percentage(cfg: GeneratorConfig, burst_rate: float | None, burst_started_at: float | None, now: float) -> float:
    if burst_rate is None or burst_started_at is None:
        return cfg.bad_event_percentage
    if now - burst_started_at < 10:
        return burst_rate
    return cfg.bad_event_percentage


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic Cisco WSA proxy events locally.")
    parser.add_argument("--json", action="store_true", help="Print the full JSON event for each generated record.")
    parser.add_argument(
        "--rate-burst",
        type=float,
        default=None,
        help="Temporarily raise the bad-event percentage to this value for 10 seconds, then revert to the configured baseline.",
    )
    args = parser.parse_args()

    cfg = GeneratorConfig()
    gen = ProxyLogGenerator(cfg)
    burst_rate = None
    burst_started_at = None

    if args.rate_burst is not None:
        burst_rate = max(0.0, min(float(args.rate_burst), 100.0))
        burst_started_at = time.monotonic()
        print(f"Applying attack burst: {cfg.bad_event_percentage}% bad -> {burst_rate}% bad for 10 seconds\n")

    print(f"Generating synthetic Cisco WSA proxy events... "
          f"({cfg.events_per_second}/sec, {cfg.bad_event_percentage}% bad baseline)\n")

    delay = 1.0 / cfg.events_per_second if cfg.events_per_second > 0 else 0
    count = 0
    good_count = 0
    bad_count = 0

    try:
        while True:
            effective_rate = effective_bad_event_percentage(cfg, burst_rate, burst_started_at, time.monotonic())
            event = gen.generate_one(bad_event_percentage=effective_rate)
            label = "BAD " if gen.is_bad(event) else "GOOD"
            print(f"{label}  {event['http_method']:6s} {event['destination_host']:35s} {event['http_status']}")

            count += 1
            if gen.is_bad(event):
                bad_count += 1
            else:
                good_count += 1

            if args.json:
                print(json.dumps(event, indent=2))

            if delay:
                time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n\nStopped. Generated {count} events: {good_count} good, {bad_count} bad "
              f"({bad_count / count * 100:.1f}% bad).")


if __name__ == "__main__":
    main()
