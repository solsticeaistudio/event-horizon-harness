"""OpenTelemetry tracing integration for Event Horizon."""
from __future__ import annotations

import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, Mapping, Optional

try:
    from opentelemetry import trace
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
    from opentelemetry.exporter.zipkin.proto.http import ZipkinExporter
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.requests import RequestsInstrumentor
    from opentelemetry.instrumentation.urllib import URLLibInstrumentor
    from opentelemetry.propagate import set_global_textmap
    from opentelemetry.propagators.b3 import B3MultiFormat
    from opentelemetry.propagators.composite import CompositePropagator
    from opentelemetry.propagators.jaeger import JaegerFormat
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter, SpanExporter
    from opentelemetry.trace import Span, SpanContext, Tracer, TracerProvider as TraceProvider
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    trace = None
    trace = None
    Span = None
    SpanContext = None
    Tracer = None
    TracerProvider = None
    SpanExporter = None
    BatchSpanProcessor = None
    ConsoleSpanExporter = None
    Resource = None
    JaegerExporter = None
    ZipkinExporter = None
    OTLPSpanExporter = None
    BatchSpanProcessor = None
    ConsoleSpanExporter = None
    TraceProvider = None
    JaegerExporter = None
    ZipkinExporter = None
    OTLPSpanExporter = None
    B3MultiFormat = None
    TraceContextTextMapPropagator = None
    JaegerFormat = None
    set_global_textmap = None
    CompositePropagator = None
    RequestsInstrumentor = None
    URLLibInstrumentor = None


@dataclass(frozen=True)
class SpanContext:
    """Immutable span context for propagation."""
    trace_id: str
    span_id: str
    trace_flags: int = 1  # sampled
    trace_state: str = ""

    def to_headers(self) -> Dict[str, str]:
        """Convert to HTTP headers for propagation."""
        return {
            "traceparent": f"00-{self.trace_id}-{self.span_id}-{self.trace_flags:02x}",
            "tracestate": self.trace_state,
        }

    @classmethod
    def from_headers(cls, headers: Mapping[str, str]) -> "SpanContext":
        """Extract span context from headers."""
        traceparent = headers.get("traceparent", "")
        parts = traceparent.split("-")
        if len(parts) >= 3:
            return cls(
                trace_id=parts[1],
                span_id=parts[2],
                trace_flags=int(parts[3], 16) if len(parts) > 3 else 1,
                trace_state=headers.get("tracestate", ""),
            )
        return cls(trace_id="", span_id="")


@dataclass
class TracingConfig:
    """Configuration for tracing."""
    service_name: str = "event-horizon"
    service_version: str = "0.1.0"
    environment: str = "development"
    sampler_type: str = "parentbased_always_on"  # always_on, always_off, parentbased_always_on, traceidratio
    sample_rate: float = 1.0
    exporter_type: str = "console"  # console, jaeger, zipkin, otlp
    jaeger_agent_host: str = "localhost"
    jaeger_agent_port: int = 6831
    zipkin_endpoint: str = "http://localhost:9411/api/v2/spans"
    otlp_endpoint: str = "http://localhost:4317"
    otlp_insecure: bool = True
    propagation_formats: list = field(default_factory=lambda: ["tracecontext", "b3", "jaeger"])


class TracingProvider:
    """OpenTelemetry tracing provider."""

    def __init__(self, config: TracingConfig):
        self.config = config
        self._provider: Optional[Any] = None
        self._tracer: Optional[Any] = None
        self._initialized = False
        self._lock = threading.Lock()

    def initialize(self) -> None:
        """Initialize the tracing provider."""
        with self._lock:
            if self._initialized:
                return

            if not OTEL_AVAILABLE:
                raise RuntimeError("OpenTelemetry not available. Install opentelemetry-api, opentelemetry-sdk, and exporters.")

            # Create resource
            resource = Resource.create({
                "service.name": self.config.service_name,
                "service.version": self.config.service_version,
                "deployment.environment": self.config.environment,
            })

            # Create tracer provider
            provider = TracerProvider(resource=resource)

            # Configure sampler
            sampler = self._create_sampler()
            provider._span_limiter = sampler  # type: ignore

            # Add exporters
            exporter = self._create_exporter()
            if exporter:
                provider.add_span_processor(BatchSpanProcessor(exporter))

            # Set as global provider
            trace.set_tracer_provider(provider)
            self._provider = provider

            # Configure propagation
            self._setup_propagation()

            # Auto-instrument
            self._auto_instrument()

            self._initialized = True

    def _create_sampler(self) -> Any:
        """Create sampler based on configuration."""
        from opentelemetry.sdk.trace.sampling import (
            ALWAYS_ON,
            ALWAYS_OFF,
            ParentBased,
            TraceIdRatioBased,
        )

        if self.config.sampler_type == "always_on":
            return ALWAYS_ON
        elif self.config.sampler_type == "always_off":
            return ALWAYS_OFF
        elif self.config.sampler_type == "parentbased_always_on":
            return ParentBased(ALWAYS_ON)
        elif self.config.sampler_type == "traceidratio":
            return ParentBased(TraceIdRatioBased(self.config.sample_rate))
        else:
            return ParentBased(ALWAYS_ON)

    def _create_exporter(self) -> Optional[Any]:
        """Create span exporter based on configuration."""
        if self.config.exporter_type == "console":
            return ConsoleSpanExporter()
        elif self.config.exporter_type == "jaeger":
            return JaegerExporter(
                agent_host_name=self.config.jaeger_agent_host,
                agent_port=self.config.jaeger_agent_port,
            )
        elif self.config.exporter_type == "zipkin":
            return ZipkinExporter(
                endpoint=self.config.zipkin_endpoint,
            )
        elif self.config.exporter_type == "otlp":
            return OTLPSpanExporter(
                endpoint=self.config.otlp_endpoint,
                insecure=self.config.otlp_insecure,
            )
        return None

    def _setup_propagation(self) -> None:
        """Configure context propagation formats."""
        propagators = []

        if "tracecontext" in self.config.propagation_formats:
            propagators.append(TraceContextTextMapPropagator())
        if "b3" in self.config.propagation_formats:
            propagators.append(B3MultiFormat())
        if "jaeger" in self.config.propagation_formats:
            propagators.append(JaegerFormat())

        if propagators:
            composite = CompositePropagator(propagators)
            set_global_textmap(composite)

    def _auto_instrument(self) -> None:
        """Enable auto-instrumentation for common libraries."""
        try:
            RequestsInstrumentor().instrument()
            URLLibInstrumentor().instrument()
        except Exception:
            pass  # Best effort

    def get_tracer(self, name: str = "event-horizon") -> Any:
        """Get a tracer instance."""
        if not self._initialized:
            self.initialize()
        return trace.get_tracer(name, self.config.service_version)

    def shutdown(self) -> None:
        """Shutdown the tracing provider."""
        if self._provider:
            self._provider.shutdown()
        self._initialized = False


# Global tracing provider
_global_tracing: Optional[TracingProvider] = None


def init_tracing(config: Optional[TracingConfig] = None) -> TracingProvider:
    """Initialize global tracing provider."""
    global _global_tracing
    _global_tracing = TracingProvider(config or TracingConfig())
    _global_tracing.initialize()
    return _global_tracing


def get_tracer(name: str = "event-horizon") -> Any:
    """Get a tracer instance."""
    global _global_tracing
    if _global_tracing is None:
        init_tracing()
    return _global_tracing.get_tracer(name)


def get_tracing_provider() -> Optional[TracingProvider]:
    """Get the global tracing provider."""
    return _global_tracing


@dataclass
class SpanContext:
    """Wrapper for span context with additional metadata."""
    trace_id: str
    span_id: str
    trace_flags: int = 1
    trace_state: str = ""

    @classmethod
    def from_current_span(cls) -> "SpanContext":
        """Create from currently active span."""
        span = trace.get_current_span()
        if span and span.get_span_context():
            ctx = span.get_span_context()
            return cls(
                trace_id=format(ctx.trace_id, "032x"),
                span_id=format(ctx.span_id, "016x"),
                trace_flags=ctx.trace_flags,
                trace_state=ctx.trace_state or "",
            )
        return cls(trace_id="", span_id="")

    def inject(self, carrier: Dict[str, str]) -> None:
        """Inject context into carrier (headers)."""
        carrier["traceparent"] = f"00-{self.trace_id}-{self.span_id}-{self.trace_flags:02x}"
        if self.trace_state:
            carrier["tracestate"] = self.trace_state

    @classmethod
    def extract(cls, carrier: Mapping[str, str]) -> "SpanContext":
        """Extract context from carrier (headers)."""
        traceparent = carrier.get("traceparent", "")
        parts = traceparent.split("-")
        if len(parts) >= 3:
            return cls(
                trace_id=parts[1],
                span_id=parts[2],
                trace_flags=int(parts[3], 16) if len(parts) > 3 else 1,
                trace_state=carrier.get("tracestate", ""),
            )
        return cls(trace_id="", span_id="")

    def inject_into_headers(self, headers: Dict[str, str]) -> None:
        """Inject into HTTP headers."""
        self.inject(headers)


@contextmanager
def trace_operation(
    name: str,
    attributes: Optional[Mapping[str, Any]] = None,
    kind: int = 0,  # SpanKind.INTERNAL
) -> Iterator[Any]:
    """Context manager for tracing an operation."""
    tracer = get_tracer()
    with tracer.start_as_current_span(name, kind=kind) as span:
        if attributes:
            for k, v in attributes.items():
                span.set_attribute(k, str(v))
        try:
            yield span
        except Exception as e:
            span.record_exception(e)
            span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
            raise


def inject_context(headers: Dict[str, str]) -> None:
    """Inject current trace context into headers."""
    span = trace.get_current_span()
    if span and span.get_span_context():
        ctx = span.get_span_context()
        headers["traceparent"] = f"00-{format(ctx.trace_id, '032x')}-{format(ctx.span_id, '016x')}-{ctx.trace_flags:02x}"
        if ctx.trace_state:
            headers["tracestate"] = ctx.trace_state


def extract_context(headers: Mapping[str, str]) -> SpanContext:
    """Extract trace context from headers."""
    traceparent = headers.get("traceparent", "")
    parts = traceparent.split("-")
    if len(parts) >= 3:
        return SpanContext(
            trace_id=parts[1],
            span_id=parts[2],
            trace_flags=int(parts[3], 16) if len(parts) > 3 else 1,
            trace_state=headers.get("tracestate", ""),
        )
    return SpanContext(trace_id="", span_id="")