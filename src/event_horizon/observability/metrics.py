"""Prometheus metrics collection for Event Horizon."""
from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Union

try:
    from prometheus_client import (
        CollectorRegistry,
        Counter as PromCounter,
        Gauge as PromGauge,
        Histogram as PromHistogram,
        Summary as PromSummary,
        generate_latest,
        CONTENT_TYPE_LATEST,
        REGISTRY,
        push_to_gateway,
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    CollectorRegistry = None
    PromCounter = None
    PromGauge = None
    PromHistogram = None
    PromSummary = None
    generate_latest = None
    CONTENT_TYPE_LATEST = "text/plain"
    REGISTRY = None
    push_to_gateway = None


class MetricType(str, Enum):
    """Metric types."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


@dataclass(frozen=True)
class MetricLabels:
    """Immutable metric labels."""
    labels: Mapping[str, str] = field(default_factory=dict)

    def with_labels(self, **kwargs: str) -> "MetricLabels":
        new_labels = {**self.labels, **kwargs}
        return MetricLabels(labels=new_labels)

    def __iter__(self):
        return iter(self.labels.items())


class Counter:
    """Counter metric that only increases."""

    def __init__(
        self,
        name: str,
        description: str,
        labels: Optional[MetricLabels] = None,
        registry: Optional[Any] = None,
    ):
        self.name = name
        self.description = description
        self.labels = labels or MetricLabels()
        self._registry = registry
        self._lock = threading.Lock()
        self._value: Dict[str, float] = {}
        self._prom_counter = None

        if PROMETHEUS_AVAILABLE:
            label_names = list(self.labels.labels.keys())
            self._prom_counter = PromCounter(
                name,
                description,
                label_names,
                registry=registry or REGISTRY,
            )

    def inc(self, value: float = 1.0, labels: Optional[Mapping[str, str]] = None) -> None:
        """Increment the counter."""
        merged_labels = self.labels.with_labels(**(labels or {})).labels
        label_key = tuple(sorted(merged_labels.items()))

        with self._lock:
            self._value[label_key] = self._value.get(label_key, 0.0) + value

        if self._prom_counter:
            if merged_labels:
                self._prom_counter.labels(**merged_labels).inc(value)
            else:
                self._prom_counter.inc(value)

    def get(self, labels: Optional[Mapping[str, str]] = None) -> float:
        """Get current counter value."""
        merged_labels = self.labels.with_labels(**(labels or {})).labels
        label_key = tuple(sorted(merged_labels.items()))
        with self._lock:
            return self._value.get(label_key, 0.0)


class Gauge:
    """Gauge metric that can go up or down."""

    def __init__(
        self,
        name: str,
        description: str,
        labels: Optional[MetricLabels] = None,
        registry: Optional[Any] = None,
    ):
        self.name = name
        self.description = description
        self.labels = labels or MetricLabels()
        self._registry = registry
        self._lock = threading.Lock()
        self._value: Dict[str, float] = {}
        self._prom_gauge = None

        if PROMETHEUS_AVAILABLE:
            label_names = list(self.labels.labels.keys())
            self._prom_gauge = PromGauge(
                name,
                description,
                label_names,
                registry=registry or REGISTRY,
            )

    def set(self, value: float, labels: Optional[Mapping[str, str]] = None) -> None:
        """Set the gauge to a specific value."""
        merged_labels = self.labels.with_labels(**(labels or {})).labels
        label_key = tuple(sorted(merged_labels.items()))

        with self._lock:
            self._value[label_key] = value

        if self._prom_gauge:
            if merged_labels:
                self._prom_gauge.labels(**merged_labels).set(value)
            else:
                self._prom_gauge.set(value)

    def inc(self, value: float = 1.0, labels: Optional[Mapping[str, str]] = None) -> None:
        """Increment the gauge."""
        merged_labels = self.labels.with_labels(**(labels or {})).labels
        label_key = tuple(sorted(merged_labels.items()))

        with self._lock:
            self._value[label_key] = self._value.get(label_key, 0.0) + value

        if self._prom_gauge:
            if merged_labels:
                self._prom_gauge.labels(**merged_labels).inc(value)
            else:
                self._prom_gauge.inc(value)

    def dec(self, value: float = 1.0, labels: Optional[Mapping[str, str]] = None) -> None:
        """Decrement the gauge."""
        self.inc(-value, labels)

    def get(self, labels: Optional[Mapping[str, str]] = None) -> float:
        """Get current gauge value."""
        merged_labels = self.labels.with_labels(**(labels or {})).labels
        label_key = tuple(sorted(merged_labels.items()))
        with self._lock:
            return self._value.get(label_key, 0.0)


class Histogram:
    """Histogram metric for tracking distributions."""

    def __init__(
        self,
        name: str,
        description: str,
        labels: Optional[MetricLabels] = None,
        buckets: Optional[List[float]] = None,
        registry: Optional[Any] = None,
    ):
        self.name = name
        self.description = description
        self.labels = labels or MetricLabels()
        self.buckets = buckets or [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        self._registry = registry
        self._lock = threading.Lock()
        self._observations: Dict[tuple, List[float]] = {}
        self._prom_histogram = None

        if PROMETHEUS_AVAILABLE:
            label_names = list(self.labels.labels.keys())
            self._prom_histogram = PromHistogram(
                name,
                description,
                label_names,
                buckets=self.buckets,
                registry=registry or REGISTRY,
            )

    def observe(self, value: float, labels: Optional[Mapping[str, str]] = None) -> None:
        """Record an observation."""
        merged_labels = self.labels.with_labels(**(labels or {})).labels
        label_key = tuple(sorted(merged_labels.items()))

        with self._lock:
            if label_key not in self._observations:
                self._observations[label_key] = []
            self._observations[label_key].append(value)

        if self._prom_histogram:
            if merged_labels:
                self._prom_histogram.labels(**merged_labels).observe(value)
            else:
                self._prom_histogram.observe(value)

    @contextmanager
    def time(self, labels: Optional[Mapping[str, str]] = None):
        """Context manager to time a block of code."""
        start = time.perf_counter()
        try:
            yield
        finally:
            duration = time.perf_counter() - start
            self.observe(duration, labels)

    def get_stats(self, labels: Optional[Mapping[str, str]] = None) -> Dict[str, float]:
        """Get histogram statistics."""
        merged_labels = self.labels.with_labels(**(labels or {})).labels
        label_key = tuple(sorted(merged_labels.items()))

        with self._lock:
            values = self._observations.get(label_key, [])

        if not values:
            return {"count": 0, "sum": 0.0, "min": 0.0, "max": 0.0, "avg": 0.0}

        return {
            "count": len(values),
            "sum": sum(values),
            "min": min(values),
            "max": max(values),
            "avg": sum(values) / len(values),
        }


class Summary:
    """Summary metric for quantile estimation."""

    def __init__(
        self,
        name: str,
        description: str,
        labels: Optional[MetricLabels] = None,
        quantiles: Optional[List[float]] = None,
        max_age_seconds: float = 600.0,
        age_buckets: int = 5,
        registry: Optional[Any] = None,
    ):
        self.name = name
        self.description = description
        self.labels = labels or MetricLabels()
        self.quantiles = quantiles or [0.5, 0.9, 0.95, 0.99]
        self.max_age_seconds = max_age_seconds
        self._registry = registry
        self._lock = threading.Lock()
        self._observations: Dict[tuple, List[tuple]] = {}  # label_key -> [(value, timestamp)]
        self._prom_summary = None

        if PROMETHEUS_AVAILABLE:
            label_names = list(self.labels.labels.keys())
            self._prom_summary = PromSummary(
                name,
                description,
                label_names,
                quantiles=self.quantiles,
                registry=registry or REGISTRY,
            )

    def observe(self, value: float, labels: Optional[Mapping[str, str]] = None) -> None:
        """Record an observation."""
        merged_labels = self.labels.with_labels(**(labels or {})).labels
        label_key = tuple(sorted(merged_labels.items()))
        now = time.time()

        with self._lock:
            if label_key not in self._observations:
                self._observations[label_key] = []
            self._observations[label_key].append((value, now))
            self._prune_old(label_key, now)

        if self._prom_summary:
            if merged_labels:
                self._prom_summary.labels(**merged_labels).observe(value)
            else:
                self._prom_summary.observe(value)

    def _prune_old(self, label_key: tuple, now: float) -> None:
        """Remove observations older than max_age_seconds."""
        if label_key in self._observations:
            self._observations[label_key] = [
                (v, t) for v, t in self._observations[label_key]
                if now - t <= self.max_age_seconds
            ]

    def get_quantiles(self, labels: Optional[Mapping[str, str]] = None) -> Dict[str, float]:
        """Calculate quantiles from observations."""
        merged_labels = self.labels.with_labels(**(labels or {})).labels
        label_key = tuple(sorted(merged_labels.items()))

        with self._lock:
            observations = self._observations.get(label_key, [])
            now = time.time()
            # Prune old
            observations = [(v, t) for v, t in observations if now - t <= self.max_age_seconds]

        if not observations:
            return {f"p{int(q*100)}": 0.0 for q in self.quantiles}

        values = sorted([v for v, _ in observations])
        result = {}
        for q in self.quantiles:
            idx = int(q * (len(values) - 1))
            result[f"p{int(q*100)}"] = values[idx]
        return result


class MetricsCollector:
    """Central metrics registry and collector."""

    def __init__(self, registry: Optional[Any] = None):
        self._registry = registry if PROMETHEUS_AVAILABLE and registry else (REGISTRY if PROMETHEUS_AVAILABLE else None)
        self._counters: Dict[str, Counter] = {}
        self._gauges: Dict[str, Gauge] = {}
        self._histograms: Dict[str, Histogram] = {}
        self._summaries: Dict[str, Summary] = {}
        self._lock = threading.Lock()

    def counter(
        self,
        name: str,
        description: str,
        labels: Optional[MetricLabels] = None,
    ) -> Counter:
        """Create or get a counter."""
        with self._lock:
            if name not in self._counters:
                self._counters[name] = Counter(name, description, labels, self._registry)
            return self._counters[name]

    def gauge(
        self,
        name: str,
        description: str,
        labels: Optional[MetricLabels] = None,
    ) -> Gauge:
        """Create or get a gauge."""
        with self._lock:
            if name not in self._gauges:
                self._gauges[name] = Gauge(name, description, labels, self._registry)
            return self._gauges[name]

    def histogram(
        self,
        name: str,
        description: str,
        labels: Optional[MetricLabels] = None,
        buckets: Optional[List[float]] = None,
    ) -> Histogram:
        """Create or get a histogram."""
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = Histogram(name, description, labels, buckets, self._registry)
            return self._histograms[name]

    def summary(
        self,
        name: str,
        description: str,
        labels: Optional[MetricLabels] = None,
        quantiles: Optional[List[float]] = None,
        max_age_seconds: float = 600.0,
    ) -> Summary:
        """Create or get a summary."""
        with self._lock:
            if name not in self._summaries:
                self._summaries[name] = Summary(name, description, labels, quantiles=quantiles, max_age_seconds=max_age_seconds, registry=self._registry)
            return self._summaries[name]

    def get_metric(self, name: str) -> Optional[Union[Counter, Gauge, Histogram, Summary]]:
        """Get a metric by name."""
        with self._lock:
            return (
                self._counters.get(name)
                or self._gauges.get(name)
                or self._histograms.get(name)
                or self._summaries.get(name)
            )

    def export_prometheus(self) -> bytes:
        """Export metrics in Prometheus format."""
        if not PROMETHEUS_AVAILABLE:
            return b"# Prometheus client not available\n"
        return generate_latest(self._registry)

    def push_to_gateway(self, gateway_url: str, job: str, grouping_key: Optional[Dict[str, str]] = None) -> None:
        """Push metrics to Prometheus Pushgateway."""
        if not PROMETHEUS_AVAILABLE:
            raise RuntimeError("prometheus_client not available")
        push_to_gateway(gateway_url, job=job, registry=self._registry, grouping_key=grouping_key)


# Global metrics collector
_global_collector: Optional[MetricsCollector] = None


def init_metrics(registry: Optional[Any] = None) -> MetricsCollector:
    """Initialize the global metrics collector."""
    global _global_collector
    _global_collector = MetricsCollector(registry)
    return _global_collector


def get_metrics_collector() -> MetricsCollector:
    """Get the global metrics collector."""
    global _global_collector
    if _global_collector is None:
        _global_collector = MetricsCollector()
    return _global_collector


# Convenience functions
def counter(name: str, description: str, labels: Optional[MetricLabels] = None) -> Counter:
    return get_metrics_collector().counter(name, description, labels)


def gauge(name: str, description: str, labels: Optional[MetricLabels] = None) -> Gauge:
    return get_metrics_collector().gauge(name, description, labels)


def histogram(name: str, description: str, labels: Optional[MetricLabels] = None, buckets: Optional[List[float]] = None) -> Histogram:
    return get_metrics_collector().histogram(name, description, labels, buckets)


def summary(name: str, description: str, labels: Optional[MetricLabels] = None, quantiles: Optional[List[float]] = None) -> Summary:
    return get_metrics_collector().summary(name, description, labels, quantiles)