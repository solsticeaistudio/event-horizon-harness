"""Grafana dashboard templates for Event Horizon."""
from __future__ import annotations

import json
from typing import Any, Dict


def get_recorder_dashboard() -> Dict[str, Any]:
    """Get Grafana dashboard for recorder metrics."""
    return {
        "dashboard": {
            "title": "Event Horizon Recorder",
            "tags": ["event-horizon", "recorder"],
            "timezone": "utc",
            "panels": [
                {
                    "id": 1,
                    "title": "Events per Second",
                    "type": "graph",
                    "datasource": "Prometheus",
                    "targets": [{
                        "expr": "rate(eh_events_total[5m])",
                        "legendFormat": "{{event_type}}",
                    }],
                    "xaxis": {"mode": "time"},
                    "yaxes": [{"format": "ops"}, {"format": "short"}],
                },
                {
                    "id": 2,
                    "title": "Event Processing Latency",
                    "type": "graph",
                    "datasource": "Prometheus",
                    "targets": [{
                        "expr": "histogram_quantile(0.99, rate(eh_recorder_latency_bucket[5m]))",
                        "legendFormat": "p99",
                    }, {
                        "expr": "histogram_quantile(0.95, rate(eh_recorder_latency_bucket[5m]))",
                        "legendFormat": "p95",
                    }, {
                        "expr": "histogram_quantile(0.5, rate(eh_recorder_latency_bucket[5m]))",
                        "legendFormat": "p50",
                    }],
                    "xaxis": {"mode": "time"},
                    "yaxes": [{"format": "s", "logBase": 10}, {"format": "short"}],
                },
                {
                    "id": 3,
                    "title": "Event Chain Integrity",
                    "type": "stat",
                    "datasource": "Prometheus",
                    "targets": [{
                        "expr": "eh_recorder_chain_valid",
                        "legendFormat": "Chain Valid",
                    }],
                    "fieldConfig": {
                        "defaults": {
                            "mappings": [{"type": "value", "options": {"0": "INVALID", "1": "VALID"}}],
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "red", "value": None},
                                    {"color": "green", "value": 1},
                                ],
                            },
                        },
                    },
                },
                {
                    "id": 4,
                    "title": "Event Chain Length",
                    "type": "graph",
                    "datasource": "Prometheus",
                    "targets": [{
                        "expr": "eh_recorder_chain_length",
                        "legendFormat": "Chain Length",
                    }],
                    "xaxis": {"mode": "time"},
                    "yaxes": [{"format": "short"}, {"format": "short"}],
                },
            ],
            "time": {"from": "now-1h", "to": "now"},
            "refresh": "10s",
        },
        "overwrite": True,
    }


def get_broker_dashboard() -> Dict[str, Any]:
    """Get Grafana dashboard for broker metrics."""
    return {
        "dashboard": {
            "title": "Event Horizon Broker",
            "tags": ["event-horizon", "broker"],
            "timezone": "utc",
            "panels": [
                {
                    "id": 1,
                    "title": "Capability Issuance Rate",
                    "type": "graph",
                    "datasource": "Prometheus",
                    "targets": [{
                        "expr": "rate(eh_broker_capabilities_issued_total[5m])",
                        "legendFormat": "{{result}}",
                    }],
                    "xaxis": {"mode": "time"},
                    "yaxes": [{"format": "ops"}, {"format": "short"}],
                },
                {
                    "id": 2,
                    "title": "Capability Consumption Rate",
                    "type": "graph",
                    "datasource": "Prometheus",
                    "targets": [{
                        "expr": "rate(eh_broker_capabilities_consumed_total[5m])",
                        "legendFormat": "{{result}}",
                    }],
                    "xaxis": {"mode": "time"},
                    "yaxes": [{"format": "ops"}, {"format": "short"}],
                },
                {
                    "id": 3,
                    "title": "Active Capabilities",
                    "type": "graph",
                    "datasource": "Prometheus",
                    "targets": [{
                        "expr": "eh_broker_active_capabilities",
                        "legendFormat": "Active",
                    }],
                    "xaxis": {"mode": "time"},
                    "yaxes": [{"format": "short"}, {"format": "short"}],
                },
                {
                    "id": 4,
                    "title": "Authority Decisions",
                    "type": "graph",
                    "datasource": "Prometheus",
                    "targets": [{
                        "expr": "rate(eh_broker_authority_decisions_total[5m])",
                        "legendFormat": "{{result}}",
                    }],
                    "xaxis": {"mode": "time"},
                    "yaxes": [{"format": "ops"}, {"format": "short"}],
                },
            ],
            "time": {"from": "now-1h", "to": "now"},
            "refresh": "10s",
        },
        "overwrite": True,
    }


def get_replay_dashboard() -> Dict[str, Any]:
    """Get Grafana dashboard for replay service metrics."""
    return {
        "dashboard": {
            "title": "Event Horizon Replay",
            "tags": ["event-horizon", "replay"],
            "timezone": "utc",
            "panels": [
                {
                    "id": 1,
                    "title": "Replay Requests Rate",
                    "type": "graph",
                    "datasource": "Prometheus",
                    "targets": [{
                        "expr": "rate(eh_replay_requests_total[5m])",
                        "legendFormat": "{{operation}} - {{result}}",
                    }],
                    "xaxis": {"mode": "time"},
                    "yaxes": [{"format": "ops"}, {"format": "short"}],
                },
                {
                    "id": 2,
                    "title": "Checkpoint Lag",
                    "type": "graph",
                    "datasource": "Prometheus",
                    "targets": [{
                        "expr": "eh_replay_checkpoint_lag",
                        "legendFormat": "{{instance}}",
                    }],
                    "xaxis": {"mode": "time"},
                    "yaxes": [{"format": "short"}, {"format": "short"}],
                },
                {
                    "id": 3,
                    "title": "Leader Election",
                    "type": "graph",
                    "datasource": "Prometheus",
                    "targets": [{
                        "expr": "eh_raft_leader_changes_total",
                        "legendFormat": "Leader Changes",
                    }],
                    "xaxis": {"mode": "time"},
                    "yaxes": [{"format": "short"}, {"format": "short"}],
                },
                {
                    "id": 4,
                    "title": "Raft State",
                    "type": "stat",
                    "datasource": "Prometheus",
                    "targets": [{
                        "expr": "eh_raft_state",
                        "legendFormat": "State",
                    }],
                    "fieldConfig": {
                        "defaults": {
                            "mappings": [
                                {"type": "value", "options": {"0": "FOLLOWER", "1": "CANDIDATE", "2": "LEADER"}}
                            ],
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "gray", "value": None},
                                    {"color": "blue", "value": 1},
                                    {"color": "green", "value": 2},
                                ],
                            },
                        },
                    },
                },
            ],
            "time": {"from": "now-1h", "to": "now"},
            "refresh": "10s",
        },
        "overwrite": True,
    }


def get_effect_dashboard() -> Dict[str, Any]:
    """Get Grafana dashboard for effect service metrics."""
    return {
        "dashboard": {
            "title": "Event Horizon Effect Service",
            "tags": ["event-horizon", "effect"],
            "timezone": "utc",
            "panels": [
                {
                    "id": 1,
                    "title": "Effect Requests Rate",
                    "type": "graph",
                    "datasource": "Prometheus",
                    "targets": [{
                        "expr": "rate(eh_effect_requests_total[5m])",
                        "legendFormat": "{{result}}",
                    }],
                    "xaxis": {"mode": "time"},
                    "yaxes": [{"format": "ops"}, {"format": "short"}],
                },
                {
                    "id": 2,
                    "title": "Effect Latency",
                    "type": "graph",
                    "datasource": "Prometheus",
                    "targets": [{
                        "expr": "histogram_quantile(0.99, rate(eh_effect_latency_bucket[5m]))",
                        "legendFormat": "p99",
                    }, {
                        "expr": "histogram_quantile(0.95, rate(eh_effect_latency_bucket[5m]))",
                        "legendFormat": "p95",
                    }, {
                        "expr": "histogram_quantile(0.5, rate(eh_effect_latency_bucket[5m]))",
                        "legendFormat": "p50",
                    }],
                    "xaxis": {"mode": "time"},
                    "yaxes": [{"format": "s", "logBase": 10}, {"format": "short"}],
                },
                {
                    "id": 3,
                    "title": "Effect Throughput",
                    "type": "graph",
                    "datasource": "Prometheus",
                    "targets": [{
                        "expr": "rate(eh_effect_bytes_total[5m])",
                        "legendFormat": "{{operation}}",
                    }],
                    "xaxis": {"mode": "time"},
                    "yaxes": [{"format": "Bps"}, {"format": "short"}],
                },
                {
                    "id": 4,
                    "title": "External Adapter Calls",
                    "type": "graph",
                    "datasource": "Prometheus",
                    "targets": [{
                        "expr": "rate(eh_external_adapter_calls_total[5m])",
                        "legendFormat": "{{adapter}} - {{result}}",
                    }],
                    "xaxis": {"mode": "time"},
                    "yaxes": [{"format": "ops"}, {"format": "short"}],
                },
            ],
            "time": {"from": "now-1h", "to": "now"},
            "refresh": "10s",
        },
        "overwrite": True,
    }


def get_system_dashboard() -> Dict[str, Any]:
    """Get Grafana dashboard for system-level metrics."""
    return {
        "dashboard": {
            "title": "Event Horizon System",
            "tags": ["event-horizon", "system"],
            "timezone": "utc",
            "panels": [
                {
                    "id": 1,
                    "title": "CPU Usage",
                    "type": "graph",
                    "datasource": "Prometheus",
                    "targets": [{
                        "expr": "rate(process_cpu_seconds_total[5m])",
                        "legendFormat": "{{instance}}",
                    }],
                    "xaxis": {"mode": "time"},
                    "yaxes": [{"format": "percentunit"}, {"format": "short"}],
                },
                {
                    "id": 2,
                    "title": "Memory Usage",
                    "type": "graph",
                    "datasource": "Prometheus",
                    "targets": [{
                        "expr": "process_resident_memory_bytes",
                        "legendFormat": "{{instance}}",
                    }],
                    "xaxis": {"mode": "time"},
                    "yaxes": [{"format": "bytes"}, {"format": "short"}],
                },
                {
                    "id": 3,
                    "title": "Open File Descriptors",
                    "type": "graph",
                    "datasource": "Prometheus",
                    "targets": [{
                        "expr": "process_open_fds",
                        "legendFormat": "{{instance}}",
                    }],
                    "xaxis": {"mode": "time"},
                    "yaxes": [{"format": "short"}, {"format": "short"}],
                },
                {
                    "id": 4,
                    "title": "Goroutines / Threads",
                    "type": "graph",
                    "datasource": "Prometheus",
                    "targets": [{
                        "expr": "go_goroutines",
                        "legendFormat": "{{instance}}",
                    }],
                    "xaxis": {"mode": "time"},
                    "yaxes": [{"format": "short"}, {"format": "short"}],
                },
            ],
            "time": {"from": "now-1h", "to": "now"},
            "refresh": "10s",
        },
        "overwrite": True,
    }


def get_all_dashboards() -> Dict[str, Dict[str, Any]]:
    """Get all Grafana dashboards."""
    return {
        "recorder": get_recorder_dashboard(),
        "broker": get_broker_dashboard(),
        "replay": get_replay_dashboard(),
        "effect": get_effect_dashboard(),
        "system": get_system_dashboard(),
    }


def export_dashboards(output_dir: str) -> None:
    """Export all dashboards to JSON files."""
    import os
    os.makedirs(output_dir, exist_ok=True)

    dashboards = get_all_dashboards()
    for name, dashboard in dashboards.items():
        filepath = os.path.join(output_dir, f"event-horizon-{name}.json")
        with open(filepath, "w") as f:
            json.dump(dashboard, f, indent=2)