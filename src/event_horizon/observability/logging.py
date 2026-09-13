"""Structured logging with correlation IDs for Event Horizon."""
from __future__ import annotations

import json
import logging
import sys
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterator, Optional, Union

try:
    from pythonjsonlogger import jsonlogger
    JSON_LOGGER_AVAILABLE = True
except ImportError:
    JSON_LOGGER_AVAILABLE = False


# Context variable for correlation ID
_correlation_id: threading.local = threading.local()
_request_id: threading.local = threading.local()
_user_id: threading.local = threading.local()


@dataclass(frozen=True)
class LogContext:
    """Immutable log context with correlation IDs."""
    correlation_id: str
    request_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    operation: Optional[str] = None
    component: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None

    def to_dict(self) -> Dict[str, str]:
        result = {"correlation_id": self.correlation_id}
        if self.request_id:
            result["request_id"] = self.request_id
        if self.user_id:
            result["user_id"] = self.user_id
        if self.session_id:
            result["session_id"] = self.session_id
        if self.operation:
            result["operation"] = self.operation
        if self.component:
            result["component"] = self.component
        if self.trace_id:
            result["trace_id"] = self.trace_id
        if self.span_id:
            result["span_id"] = self.span_id
        return result


class CorrelationIdFilter(logging.Filter):
    """Logging filter to inject correlation IDs into log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        # Add correlation ID if available
        if hasattr(_correlation_id, "value"):
            record.correlation_id = _correlation_id.value
        else:
            record.correlation_id = "-"

        if hasattr(_request_id, "value"):
            record.request_id = _request_id.value
        else:
            record.request_id = "-"

        if hasattr(_user_id, "value"):
            record.user_id = _user_id.value
        else:
            record.user_id = "-"

        # Add timestamp
        record.timestamp = datetime.utcnow().isoformat() + "Z"
        return True


class JsonFormatter(logging.Formatter):
    """JSON log formatter with correlation IDs."""

    def __init__(self, include_extra: bool = True, **kwargs):
        super().__init__()
        self.include_extra = include_extra
        self.kwargs = kwargs

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add correlation IDs
        for attr in ["correlation_id", "request_id", "user_id", "trace_id", "span_id"]:
            if hasattr(record, attr):
                value = getattr(record, attr)
                if value and value != "-":
                    record.__dict__[attr] = getattr(record, attr)

        # Add correlation fields
        for attr in ["correlation_id", "request_id", "user_id", "trace_id", "span_id"]:
            if hasattr(record, attr):
                value = getattr(record, attr)
                if value and value != "-":
                    record.__dict__[attr] = getattr(record, attr)

        # Add extra fields
        if self.include_extra:
            for key, value in record.__dict__.items():
                if key not in {
                    "name", "msg", "args", "created", "filename", "funcName",
                    "levelname", "levelno", "lineno", "module", "msecs",
                    "message", "name", "pathname", "process", "processName",
                    "relativeCreated", "thread", "threadName", "exc_info",
                    "exc_text", "stack_info", "correlation_id", "request_id",
                    "user_id", "trace_id", "span_id",
                }:
                    record.__dict__[key] = value

        return json.dumps(record.__dict__, default=str, ensure_ascii=False)


class StructuredLogger:
    """Structured logger with correlation ID support."""

    def __init__(self, name: str, logger: Optional[logging.Logger] = None):
        self.name = name
        self._logger = logger or logging.getLogger(name)
        self._context: LogContext = LogContext(correlation_id="")

    def _log(
        self,
        level: int,
        message: str,
        *args: Any,
        extra: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Log with structured context."""
        extra = extra or {}
        # Merge context
        context = self._context.to_dict()
        extra.update(context)

        # Add extra fields from kwargs
        for key, value in kwargs.items():
            if key not in ("exc_info", "stack_info", "stacklevel"):
                extra[key] = value

        self._logger.log(level, message, *args, extra=extra, **kwargs)

    def set_context(self, context: "LogContext") -> None:
        """Set the logging context."""
        self._context = context

    def bind(self, **kwargs: Any) -> "StructuredLogger":
        """Create a new logger with additional context."""
        new_logger = StructuredLogger(self.name, self._logger)
        new_logger._context = LogContext(
            correlation_id=self._context.correlation_id,
            request_id=self._context.request_id or kwargs.get("request_id"),
            user_id=self._context.user_id or kwargs.get("user_id"),
            session_id=self._context.session_id or kwargs.get("session_id"),
            operation=kwargs.get("operation", self._context.operation),
            component=kwargs.get("component", self._context.component),
            trace_id=kwargs.get("trace_id", self._context.trace_id),
            span_id=kwargs.get("span_id", self._context.span_id),
        )
        return new_logger

    def debug(self, message: str, *args: Any, **kwargs: Any) -> None:
        self._log(logging.DEBUG, message, *args, **kwargs)

    def info(self, message: str, *args: Any, **kwargs: Any) -> None:
        self._log(logging.INFO, message, *args, **kwargs)

    def warning(self, message: str, *args: Any, **kwargs: Any) -> None:
        self._log(logging.WARNING, message, *args, **kwargs)

    def error(self, message: str, *args: Any, **kwargs: Any) -> None:
        self._log(logging.ERROR, message, *args, **kwargs)

    def critical(self, message: str, *args: Any, **kwargs: Any) -> None:
        self._log(logging.CRITICAL, message, *args, **kwargs)

    def exception(self, message: str, *args: Any, **kwargs: Any) -> None:
        self._log(logging.ERROR, message, *args, exc_info=True, **kwargs)

    def log(self, level: int, message: str, *args: Any, **kwargs: Any) -> None:
        self._log(level, message, *args, **kwargs)

    def with_context(self, **kwargs: Any) -> "StructuredLogger":
        """Create a new logger with additional context."""
        return self.bind(**kwargs)


@dataclass
class LogContext:
    """Logging context with correlation IDs."""
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    request_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    operation: Optional[str] = None
    component: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None

    def to_dict(self) -> Dict[str, str]:
        result = {"correlation_id": self.correlation_id}
        if self.request_id:
            result["request_id"] = self.request_id
        if self.user_id:
            result["user_id"] = self.user_id
        if self.session_id:
            result["session_id"] = self.session_id
        if self.operation:
            result["operation"] = self.operation
        if self.component:
            result["component"] = self.component
        if self.trace_id:
            result["trace_id"] = self.trace_id
        if self.span_id:
            result["span_id"] = self.span_id
        return result


def get_correlation_id() -> str:
    """Get the current correlation ID."""
    if hasattr(_correlation_id, "value"):
        return _correlation_id.value
    return ""


def set_correlation_id(correlation_id: Optional[str] = None) -> str:
    """Set the correlation ID for the current context."""
    cid = correlation_id or str(uuid.uuid4())
    _correlation_id.value = cid
    return cid


def get_request_id() -> Optional[str]:
    """Get the current request ID."""
    if hasattr(_request_id, "value"):
        return _request_id.value
    return None


def set_request_id(request_id: Optional[str] = None) -> str:
    """Set the request ID for the current context."""
    rid = request_id or str(uuid.uuid4())
    _request_id.value = rid
    return rid


def get_user_id() -> Optional[str]:
    """Get the current user ID."""
    if hasattr(_user_id, "value"):
        return _user_id.value
    return None


def set_user_id(user_id: Optional[str]) -> None:
    """Set the user ID for the current context."""
    if user_id:
        _user_id.value = user_id
    elif hasattr(_user_id, "value"):
        delattr(_user_id, "value")


def clear_context() -> None:
    """Clear all context variables."""
    if hasattr(_correlation_id, "value"):
        delattr(_correlation_id, "value")
    if hasattr(_request_id, "value"):
        delattr(_request_id, "value")
    if hasattr(_user_id, "value"):
        delattr(_user_id, "value")


@contextmanager
def log_context(
    correlation_id: Optional[str] = None,
    request_id: Optional[str] = None,
    user_id: Optional[str] = None,
    session_id: Optional[str] = None,
    operation: Optional[str] = None,
    component: Optional[str] = None,
    trace_id: Optional[str] = None,
    span_id: Optional[str] = None,
) -> Iterator[LogContext]:
    """Context manager for structured logging context."""
    cid = set_correlation_id(correlation_id)
    rid = set_request_id(request_id)
    if session_id:
        _request_id.value = session_id  # reuse for session
    if operation:
        pass  # Could add operation tracking
    if component:
        pass

    context = LogContext(
        correlation_id=cid,
        request_id=rid,
        user_id=user_id,
        session_id=session_id,
        operation=operation,
        component=component,
        trace_id=None,  # Would come from tracing
        span_id=None,
    )

    try:
        yield LogContext(
            correlation_id=cid,
            request_id=rid,
            user_id=user_id,
            session_id=session_id,
            operation=operation,
            component=component,
            trace_id=None,
            span_id=None,
        )
    finally:
        clear_context()


class LoggerAdapter(logging.LoggerAdapter):
    """Logger adapter that automatically adds context."""

    def process(self, msg: str, kwargs: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        extra = kwargs.get("extra", {})
        # Add context
        context = {
            "correlation_id": get_correlation_id(),
            "request_id": get_request_id() or "-",
            "user_id": get_user_id() or "-",
        }
        extra.update(kwargs.get("extra", {}))
        extra.update({k: v for k, v in extra.items() if k not in ("exc_info", "stack_info", "stacklevel")})
        return super().process(msg, {"extra": extra, **kwargs})


def init_logging(
    level: int = logging.INFO,
    json_format: bool = True,
    include_timestamp: bool = True,
    output_stream: Optional[Union[sys.stdout, sys.stderr]] = None,
    format_string: Optional[str] = None,
) -> None:
    """Initialize structured logging."""
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(output_stream or sys.stdout)

    if json_format:
        formatter = JsonFormatter(include_extra=True)
    else:
        if format_string:
            formatter = logging.Formatter(format_string)
        else:
            fmt = "%(timestamp)s %(levelname)s [%(correlation_id)s] %(name)s: %(message)s"
            formatter = logging.Formatter(fmt)

    handler.setFormatter(formatter)
    handler.addFilter(CorrelationIdFilter())
    root_logger.addHandler(handler)

    # Set default level for third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)


def get_logger(name: str) -> StructuredLogger:
    """Get a structured logger instance."""
    return StructuredLogger(name)


def get_logger(name: str) -> StructuredLogger:
    """Get a structured logger instance (alias)."""
    return get_logger(name)


# Convenience functions
def debug(message: str, *args: Any, **kwargs: Any) -> None:
    get_logger("event-horizon").debug(message, *args, **kwargs)


def info(message: str, *args: Any, **kwargs: Any) -> None:
    get_logger("event-horizon").info(message, *args, **kwargs)


def warning(message: str, *args: Any, **kwargs: Any) -> None:
    get_logger("event-horizon").warning(message, *args, **kwargs)


def error(message: str, *args: Any, **kwargs: Any) -> None:
    get_logger("event-horizon").error(message, *args, **kwargs)


def critical(message: str, *args: Any, **kwargs: Any) -> None:
    get_logger("event-horizon").critical(message, *args, **kwargs)


def exception(message: str, *args: Any, **kwargs: Any) -> None:
    get_logger("event-horizon").exception(message, *args, **kwargs)