"""Observability stack: metrics, tracing, logging, alerting."""
from __future__ import annotations

from .metrics import (
    MetricsCollector,
    Counter,
    Histogram,
    Gauge,
    Summary,
    get_metrics_collector,
    init_metrics,
)
from .tracing import (
    TracingProvider,
    get_tracer,
    init_tracing,
    SpanContext,
)
from .logging import (
    StructuredLogger,
    get_logger,
    init_logging,
    LogContext,
)
from .alerting import (
    AlertManager,
    AlertRule,
    AlertSeverity,
    create_default_alert_manager,
)

__all__ = [
    "MetricsCollector",
    "Counter",
    "Histogram",
    "Gauge",
    "Summary",
    "get_metrics_collector",
    "init_metrics",
    "TracingProvider",
    "get_tracer",
    "init_tracing",
    "SpanContext",
    "StructuredLogger",
    "get_logger",
    "init_logging",
    "LogContext",
    "AlertManager",
    "AlertRule",
    "AlertSeverity",
    "create_default_alert_manager",
]