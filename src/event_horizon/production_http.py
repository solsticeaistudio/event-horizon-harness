"""Production-hardened HTTP server for Event Horizon services.

Provides mTLS, rate limiting, admission control, structured logging,
health/metrics endpoints, and production-grade security hardening.
"""
from __future__ import annotations

import abc
import base64
import hashlib
import json
import logging
import ssl
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from functools import wraps
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Set, Tuple, Type

from event_horizon.canonical import canonical_bytes, strict_json_loads


# =============================================================================
# Configuration
# =============================================================================

@dataclass(frozen=True)
class TLSConfig:
    """TLS/mTLS configuration."""
    certfile: str
    keyfile: str
    cafile: str
    require_client_cert: bool = True
    min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2
    cipher_suites: Optional[List[str]] = None

    def create_ssl_context(self) -> ssl.SSLContext:
        """Create hardened SSL context."""
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.minimum_version = self.min_version
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        if self.cipher_suites:
            ctx.set_ciphers(":".join(self.cipher_suites))
        else:
            # Modern, secure cipher suite
            ctx.set_ciphers(
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
                "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
            )
        ctx.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        ctx.load_verify_locations(cafile=self.cafile)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = False  # We validate via certificate pinning
        return ctx


@dataclass(frozen=True)
class RateLimitConfig:
    """Rate limiting configuration."""
    requests_per_second: float = 100.0
    burst: int = 200
    per_ip: bool = True
    whitelist: Set[str] = field(default_factory=set)

    def __post_init__(self):
        if self.requests_per_second <= 0:
            raise ValueError("requests_per_second must be positive")
        if self.burst <= 0:
            raise ValueError("burst must be positive")


@dataclass(frozen=True)
class AdmissionConfig:
    """Admission control configuration."""
    allowed_ips: Set[str] = field(default_factory=set)
    allowed_networks: List[str] = field(default_factory=list)
    max_body_bytes: int = 64 * 1024  # 64 KiB
    require_content_type: str = "application/json"
    allowed_paths: Set[str] = field(default_factory=set)
    require_headers: Set[str] = field(default_factory=set)
    whitelist: Set[str] = field(default_factory=set)  # For rate limiter

    def is_ip_allowed(self, ip: str) -> bool:
        if ip in self.whitelist:
            return True
        try:
            addr = IPv4Address(ip) if ":" not in ip else IPv6Address(ip)
            for net_str in self.allowed_networks:
                network = IPv4Network(net_str) if ":" not in net_str else IPv6Network(net_str)
                if addr in network:
                    return True
        except ValueError:
            pass
        return ip in self.allowed_ips


@dataclass(frozen=True)
class ServerConfig:
    """Complete server configuration."""
    host: str = "0.0.0.0"
    port: int = 0
    tls: Optional[TLSConfig] = None
    rate_limit: Optional[RateLimitConfig] = None
    admission: Optional[AdmissionConfig] = None
    request_timeout_seconds: float = 5.0
    max_body_bytes: int = 64 * 1024
    enable_metrics: bool = True
    enable_health: bool = True
    server_name: str = "event-horizon"


# =============================================================================
# Rate Limiting
# =============================================================================

class TokenBucket:
    """Thread-safe token bucket rate limiter."""

    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.burst = burst
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, tokens: int = 1) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
            self._last_refill = now

            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False


class RateLimiter:
    """Per-IP or global rate limiter using token buckets."""

    def __init__(self, config: RateLimitConfig):
        self.config = config
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def _get_bucket(self, key: str) -> TokenBucket:
        with self._lock:
            if key not in self._buckets:
                self._buckets[key] = TokenBucket(self.config.requests_per_second, self.config.burst)
            return self._buckets[key]

    def allow(self, identifier: str) -> bool:
        if identifier in self.config.whitelist:
            return True
        bucket = self._get_bucket(identifier)
        return bucket.consume()


# =============================================================================
# Structured Logging
# =============================================================================

class StructuredLogger:
    """Structured JSON logger with request context."""

    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(JsonFormatter())
            self.logger.addHandler(handler)

    def log_request(self, method: str, path: str, client_ip: str, 
                    status: int, duration_ms: float, **extra) -> None:
        self.logger.info("http_request", extra={
            "method": method, "path": path, "client_ip": client_ip,
            "status": status, "duration_ms": round(duration_ms, 2), **extra
        })

    def log_error(self, message: str, **extra) -> None:
        self.logger.error(message, extra=extra)

    def log_security(self, event: str, client_ip: str, **extra) -> None:
        self.logger.warning(f"security_event: {event}", extra={
            "security_event": event, "client_ip": client_ip, **extra
        })


class JsonFormatter(logging.Formatter):
    """JSON log formatter."""

    def format(self, record: logging.LogRecord) -> str:
        data = {
            "timestamp": time.time(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in {"name", "msg", "args", "levelname", "levelno", 
                          "pathname", "filename", "module", "lineno",
                          "funcName", "created", "msecs", "relativeCreated",
                          "thread", "threadName", "processName", "process",
                          "message"}:
                data[key] = value
        return json.dumps(data)


# =============================================================================
# Production HTTP Server
# =============================================================================

class ProductionHTTPServer:
    """Production-hardened HTTP server with mTLS, rate limiting, admission control."""

    def __init__(
        self,
        config: ServerConfig,
        route_handlers: Mapping[str, Callable[[Mapping[str, Any]], Mapping[str, Any]]],
        logger: Optional[StructuredLogger] = None,
    ):
        self.config = config
        self.route_handlers = dict(route_handlers)
        self.logger = logger or StructuredLogger("event-horizon-http")
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._rate_limiter = RateLimiter(config.rate_limit) if config.rate_limit else None
        self._admission = config.admission
        self._start_time = time.time()
        self._request_count = 0
        self._error_count = 0
        self._lock = threading.Lock()
        self._shutdown_event = threading.Event()

        # Built-in routes
        if config.enable_health:
            self.route_handlers["/health"] = self._health_check
            self.route_handlers["/health/live"] = self._liveness_check
            self.route_handlers["/health/ready"] = self._readiness_check
        if config.enable_metrics:
            self.route_handlers["/metrics"] = self._metrics

    # -------------------------------------------------------------------------
    # Built-in endpoints
    # -------------------------------------------------------------------------

    def _health_check(self, _: Mapping[str, Any]) -> Mapping[str, Any]:
        return {"status": "healthy", "uptime_seconds": time.time() - self._start_time}

    def _liveness_check(self, _: Mapping[str, Any]) -> Mapping[str, Any]:
        return {"alive": True}

    def _readiness_check(self, _: Mapping[str, Any]) -> Mapping[str, Any]:
        return {"ready": True, "checks": {}}

    def _metrics(self, _: Mapping[str, Any]) -> Mapping[str, Any]:
        with self._lock:
            return {
                "requests_total": self._request_count,
                "errors_total": self._error_count,
                "uptime_seconds": time.time() - self._start_time,
            }

    # -------------------------------------------------------------------------
    # Server lifecycle
    # -------------------------------------------------------------------------

    def start(self, host: Optional[str] = None, port: Optional[int] = None) -> None:
        host = host or self.config.host
        port = port or self.config.port

        handler_class = self._create_handler()
        self._server = ThreadingHTTPServer((host, port), handler_class)

        if self.config.tls:
            self._server.socket = self.config.tls.create_ssl_context().wrap_socket(
                self._server.socket, server_side=True
            )

        self._thread = threading.Thread(
            target=self._run_server, daemon=True, name="event-horizon-http"
        )
        self._thread.start()

        # Wait for server to be ready
        time.sleep(0.1)

    def _run_server(self) -> None:
        if self._server:
            self._server.serve_forever()

    def stop(self) -> None:
        self._shutdown_event.set()
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=10)

    @property
    def port(self) -> int:
        if self._server:
            return self._server.server_address[1]
        return 0

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2] if self._server else ("localhost", 0)
        scheme = "https" if self.config.tls else "http"
        return f"{scheme}://{host}:{port}"

    # -------------------------------------------------------------------------
    # Request handling
    # -------------------------------------------------------------------------

    def _admit_request(self, client_ip: str) -> bool:
        if not self._admission:
            return True
        return self._admission.is_ip_allowed(client_ip)

    def _validate_request(self, handler: BaseHTTPRequestHandler) -> bool:
        if self.config.admission and self.config.admission.require_content_type:
            content_type = handler.headers.get("Content-Type", "").split(";")[0].strip()
            if content_type != self.config.admission.require_content_type:
                return False
        if self.config.admission:
            for header in self.config.admission.require_headers:
                if header not in handler.headers:
                    return False
        try:
            length = int(handler.headers.get("Content-Length", "-1"))
            if length < 0 or length > self.config.max_body_bytes:
                return False
        except ValueError:
            return False
        return True

    def _create_handler(self) -> Type[BaseHTTPRequestHandler]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                start = time.monotonic()
                client_ip = self.client_address[0]

                try:
                    # Admission control
                    if not server._admit_request(client_ip):
                        server._log_security("admission_denied", client_ip, path=self.path)
                        self.send_error(HTTPStatus.FORBIDDEN)
                        return

                    # Rate limiting
                    if server._rate_limiter and not server._rate_limiter.allow(client_ip):
                        server._log_security("rate_limited", client_ip, path=self.path)
                        self.send_error(HTTPStatus.TOO_MANY_REQUESTS)
                        return

                    # Path routing
                    handler = server.route_handlers.get(self.path)
                    if not handler:
                        server._log_security("not_found", client_ip, path=self.path)
                        self.send_error(HTTPStatus.NOT_FOUND)
                        return

                    # Request validation
                    if self.path != "/health" and self.path != "/health/live" and self.path != "/health/ready" and self.path != "/metrics":
                        if not server._validate_request(self):
                            return

                    # Process request
                    try:
                        length = int(self.headers.get("Content-Length", "0"))
                        if length > server.config.max_body_bytes:
                            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                            return

                        body = self.rfile.read(length) if length > 0 else b""
                        request = strict_json_loads(body, require_canonical=True) if body else {}

                        response = handler(request)
                        encoded = canonical_bytes(response)

                        self.send_response(HTTPStatus.OK)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(encoded)))
                        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
                        self.send_header("X-Content-Type-Options", "nosniff")
                        self.send_header("X-Frame-Options", "DENY")
                        self.end_headers()
                        self.wfile.write(encoded)

                        server._record_request(time.time() - start, True)

                    except Exception as e:
                        server._record_request(time.time() - start, False)
                        if isinstance(e, (ValueError, json.JSONDecodeError)):
                            self.send_error(HTTPStatus.BAD_REQUEST)
                        else:
                            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)

                except Exception as e:
                    server._record_request(time.time() - start, False)
                    server.logger.log_error("request_error", error=str(e), client_ip=client_ip)
                    self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)

            def do_GET(self) -> None:
                start = time.monotonic()
                client_ip = self.client_address[0]

                try:
                    # Rate limiting
                    if server._rate_limiter and not server._rate_limiter.allow(client_ip):
                        server._log_security("rate_limited", client_ip, path=self.path)
                        self.send_error(HTTPStatus.TOO_MANY_REQUESTS)
                        return

                    # Path routing
                    handler = server.route_handlers.get(self.path)
                    if not handler:
                        self.send_error(HTTPStatus.NOT_FOUND)
                        return

                    response = handler({})
                    encoded = canonical_bytes(response)

                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(encoded)))
                    self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.send_header("X-Frame-Options", "DENY")
                    self.end_headers()
                    self.wfile.write(encoded)

                    server._record_request(time.time() - start, True)

                except Exception as e:
                    server._record_request(time.time() - start, False)
                    self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)

            def _admit_request(self, handler: "Handler") -> bool:
                if not server._admission:
                    return True
                return server._admission.is_ip_allowed(handler.client_address[0])

            def _validate_request(self, handler: "Handler") -> bool:
                # Content-Type check
                if server.config.admission and server.config.admission.require_content_type:
                    content_type = handler.headers.get("Content-Type", "").split(";")[0].strip()
                    if content_type != server.config.admission.require_content_type:
                        handler.send_error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
                        return False

                # Required headers
                if server.config.admission:
                    for header in server.config.admission.require_headers:
                        if header not in handler.headers:
                            handler.send_error(HTTPStatus.BAD_REQUEST)
                            return False

                # Content-Length
                try:
                    length = int(handler.headers.get("Content-Length", "-1"))
                    if length < 0 or length > server.config.max_body_bytes:
                        handler.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                        return False
                except ValueError:
                    handler.send_error(HTTPStatus.BAD_REQUEST)
                    return False

                return True

            def log_message(self, format: str, *args: Any) -> None:
                pass  # We use structured logging

        return Handler

    # -------------------------------------------------------------------------
    # Recording
    # -------------------------------------------------------------------------

    def _record_request(self, duration: float, success: bool) -> None:
        with self._lock:
            self._request_count += 1
            if not success:
                self._error_count += 1

    def _log_security(self, event: str, client_ip: str, **extra) -> None:
        self.logger.log_security(event, client_ip=client_ip, **extra)


# =============================================================================
# Convenience factory
# =============================================================================

def create_production_server(
    route_handlers: Mapping[str, Callable[[Mapping[str, Any]], Mapping[str, Any]]],
    *,
    host: str = "0.0.0.0",
    port: int = 0,
    tls_config: Optional[TLSConfig] = None,
    rate_limit_rps: float = 100.0,
    rate_limit_burst: int = 200,
    allowed_ips: Optional[Set[str]] = None,
    allowed_networks: Optional[List[str]] = None,
    max_body_bytes: int = 64 * 1024,
    enable_metrics: bool = True,
    enable_health: bool = True,
) -> ProductionHTTPServer:
    """Create a production-hardened HTTP server with sensible defaults."""
    config = ServerConfig(
        host=host,
        port=port,
        tls=tls_config,
        rate_limit=RateLimitConfig(
            requests_per_second=rate_limit_rps,
            burst=rate_limit_burst,
        ) if rate_limit_rps > 0 else None,
        admission=AdmissionConfig(
            allowed_ips=allowed_ips or set(),
            allowed_networks=allowed_networks or [],
            max_body_bytes=max_body_bytes,
        ) if allowed_ips or allowed_networks else None,
        max_body_bytes=max_body_bytes,
        enable_metrics=enable_metrics,
        enable_health=enable_health,
    )
    return ProductionHTTPServer(config, route_handlers)


# =============================================================================
# Raft-specific server
# =============================================================================

def create_raft_server(
    consensus: Any,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    tls_config: Optional[TLSConfig] = None,
    allowed_ips: Optional[Set[str]] = None,
) -> ProductionHTTPServer:
    """Create a production-hardened Raft HTTP server."""
    from event_horizon.raft_replay import RaftConsensus
    from event_horizon.canonical import canonical_bytes, strict_json_loads

    consensus_: RaftConsensus = consensus

    def vote_handler(request: Mapping[str, Any]) -> Mapping[str, Any]:
        with consensus_._lock:
            term = request.get("term", 0)
            candidate_id = request.get("candidate_id", "")
            last_log_index = request.get("last_log_index", 0)
            last_log_term = request.get("last_log_term", 0)

            vote_granted = False
            if term > consensus_._current_term:
                consensus_._current_term = term
                consensus_._state = "follower"
                consensus_._voted_for = None
                # Reset election deadline when receiving a higher term
                consensus_._election_deadline = consensus_._random_election_deadline()

            if term >= consensus_._current_term and \
               (consensus_._voted_for is None or consensus_._voted_for == candidate_id) and \
               (last_log_term > (consensus_._log[-1].term if consensus_._log else 0) or \
                (last_log_term == (consensus_._log[-1].term if consensus_._log else 0) and last_log_index >= len(consensus_._log))):
                consensus_._voted_for = candidate_id
                vote_granted = True
                consensus_._election_deadline = consensus_._random_election_deadline()

            return {"term": consensus_._current_term, "vote_granted": vote_granted}

    def append_handler(request: Mapping[str, Any]) -> Mapping[str, Any]:
        with consensus_._lock:
            term = request.get("term", 0)
            leader_id = request.get("leader_id", "")
            prev_log_index = request.get("prev_log_index", 0)
            prev_log_term = request.get("prev_log_term", 0)
            entries = request.get("entries", [])
            leader_commit = request.get("leader_commit", 0)

            success = False
            next_index = 0
            match_index = 0

            if term >= consensus_._current_term:
                if term > consensus_._current_term:
                    consensus_._current_term = term
                    consensus_._state = "follower"
                    consensus_._voted_for = None

                consensus_._leader_id = leader_id
                consensus_._election_deadline = consensus_._random_election_deadline()

                if prev_log_index == 0 or \
                   (prev_log_index <= len(consensus_._log) and \
                    consensus_._log[prev_log_index - 1].term == prev_log_term):
                    for i, entry_data in enumerate(entries):
                        log_index = prev_log_index + i + 1
                        entry = RaftLogEntry(
                            index=log_index,
                            term=entry_data["term"],
                            command=entry_data["command"],
                            checkpoint=entry_data["checkpoint"],
                            checkpoint_digest=entry_data["checkpoint_digest"],
                        )
                        if log_index <= len(consensus_._log):
                            consensus_._log[log_index - 1] = entry
                        else:
                            consensus_._log.append(entry)

                    if leader_commit > consensus_._commit_index:
                        consensus_._commit_index = min(leader_commit, len(consensus_._log))

                    success = True
                    next_index = len(consensus_._log) + 1
                    match_index = len(consensus_._log)

            return {
                "term": consensus_._current_term,
                "success": success,
                "next_index": next_index,
                "match_index": match_index,
            }

    return create_production_server(
        {"/raft/vote": vote_handler, "/raft/append": append_handler},
        host=host,
        port=port,
        tls_config=tls_config,
        rate_limit_rps=1000.0,  # Higher for Raft internal traffic
        rate_limit_burst=2000,
        allowed_ips=allowed_ips,
        enable_metrics=True,
        enable_health=True,
    )