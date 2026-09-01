from types import SimpleNamespace

from producer.local_test import effective_bad_event_percentage


def test_burst_uses_spike_while_active():
    cfg = SimpleNamespace(bad_event_percentage=5)

    assert effective_bad_event_percentage(cfg, 40, 100.0, 100.0) == 40
    assert effective_bad_event_percentage(cfg, 40, 100.0, 108.0) == 40


def test_burst_reverts_to_baseline_after_10_seconds():
    cfg = SimpleNamespace(bad_event_percentage=5)

    assert effective_bad_event_percentage(cfg, 40, 100.0, 110.0) == 5
