"""Alerting system for Event Horizon."""
from __future__ import annotations

import json
import smtplib
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from enum import Enum
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False


class AlertSeverity(str, Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass(frozen=True)
class AlertRule:
    """Alert rule definition."""
    name: str
    description: str
    severity: AlertSeverity
    condition: str  # PromQL expression or callable
    threshold: Union[float, Dict[str, float]]
    duration: str = "5m"  # How long condition must persist
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True

    def matches(self, metrics: Mapping[str, float]) -> bool:
        """Check if alert condition is met."""
        try:
            # Simple threshold check for now
            if isinstance(self.threshold, (int, float)):
                # Simple numeric comparison
                metric_name = self.condition
                if metric_name in metrics:
                    value = metrics[metric_name]
                    return value > self.threshold
            return False
        except Exception:
            return False


class AlertSeverityLevel(Enum):
    """Alert severity levels for sorting."""
    INFO = 1
    WARNING = 2
    CRITICAL = 3
    EMERGENCY = 4


@dataclass
class Alert:
    """An active alert."""
    rule_name: str
    severity: AlertSeverity
    message: str
    labels: Dict[str, str]
    annotations: Dict[str, str]
    starts_at: datetime
    ends_at: Optional[datetime] = None
    fingerprint: str = ""
    status: str = "firing"  # firing, resolved
    value: Optional[float] = None

    def __post_init__(self):
        if not self.fingerprint:
            import hashlib
            data = f"{self.rule_name}:{sorted(self.labels.items())}"
            self.fingerprint = hashlib.md5(data.encode()).hexdigest()[:16]


class AlertManager:
    """Alert manager for firing and resolving alerts."""

    def __init__(
        self,
        rules: Optional[List[AlertRule]] = None,
        notification_channels: Optional[Dict[str, Callable]] = None,
        evaluation_interval: int = 30,
    ):
        self.rules = {rule.name: rule for rule in (rules or [])}
        self.notification_channels = notification_channels or {}
        self.evaluation_interval = evaluation_interval
        self._alerts: Dict[str, Alert] = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callbacks: List[Callable[[Alert], None]] = []

    def add_rule(self, rule: AlertRule) -> None:
        """Add an alert rule."""
        with self._lock:
            self.rules[rule.name] = rule

    def remove_rule(self, name: str) -> bool:
        """Remove an alert rule."""
        with self._lock:
            if name in self.rules:
                del self.rules[name]
                return True
            return False

    def add_notification_channel(self, name: str, callback: Callable[[Alert], None]) -> None:
        """Add a notification callback."""
        self.notification_channels[name] = callback

    def add_callback(self, callback: Callable[[Alert], None]) -> None:
        """Add a callback for alert events."""
        self._callbacks.append(callback)

    def evaluate(self, metrics: Mapping[str, float]) -> List[Alert]:
        """Evaluate all rules against current metrics."""
        fired_alerts = []

        with self._lock:
            for rule in self.rules.values():
                if not rule.enabled:
                    continue

                if rule.matches(metrics):
                    # Alert condition met
                    alert = Alert(
                        rule_name=rule.name,
                        severity=rule.severity,
                        message=rule.annotations.get(
                            "summary", f"Alert {rule.name} triggered"
                        ),
                        labels={**rule.labels, "alertname": rule.name},
                        annotations=rule.annotations,
                        starts_at=datetime.utcnow(),
                        value=metrics.get(rule.condition),
                    )

                    # Check if already firing
                    if alert.fingerprint in self._alerts:
                        existing = self._alerts[alert.fingerprint]
                        if existing.status == "firing":
                            continue  # Already firing

                    self._alerts[alert.fingerprint] = alert
                    fired_alerts.append(alert)

            # Check for resolved alerts
            resolved = []
            for fp, alert in list(self._alerts.items()):
                if alert.status == "firing":
                    rule = self.rules.get(alert.rule_name)
                    if rule and not rule.matches({}):
                        alert.status = "resolved"
                        alert.ends_at = datetime.utcnow()
                        resolved.append(alert)

            return fired_alerts

    def _notify(self, alerts: List[Alert]) -> None:
        """Send notifications for fired alerts."""
        for alert in alerts:
            for callback in self._callbacks:
                try:
                    callback(alert)
                except Exception:
                    pass  # Best effort

            for name, channel in self.notification_channels.items():
                try:
                    channel(alert)
                except Exception:
                    pass

    def start(self) -> None:
        """Start the alert evaluation loop."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the alert evaluation loop."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        """Background evaluation loop."""
        while self._running:
            try:
                # Would need access to metrics - in practice, this would be integrated
                # with the metrics collector
                time.sleep(self.evaluation_interval)
            except Exception:
                pass

    def get_active_alerts(self) -> List[Alert]:
        """Get all currently firing alerts."""
        with self._lock:
            return [a for a in self._alerts.values() if a.status == "firing"]

    def get_alert_history(self, limit: int = 100) -> List[Alert]:
        """Get recent alert history."""
        with self._lock:
            all_alerts = sorted(
                self._alerts.values(),
                key=lambda a: a.starts_at,
                reverse=True
            )
            return all_alerts[:limit]

    def silence_alert(self, fingerprint: str, duration: int = 3600) -> bool:
        """Silence an alert for a duration."""
        with self._lock:
            if fingerprint in self._alerts:
                alert = self._alerts[fingerprint]
                alert.annotations["silenced_until"] = str(
                    datetime.utcnow().timestamp() + duration
                )
                return True
            return False


# Default alert rules for Event Horizon
DEFAULT_ALERT_RULES = [
    AlertRule(
        name="high_error_rate",
        description="High error rate detected",
        severity=AlertSeverity.CRITICAL,
        condition="error_rate",
        threshold=0.05,  # 5% error rate
        duration="2m",
        annotations={
            "summary": "High error rate detected",
            "description": "Error rate exceeded 5% for more than 2 minutes",
        },
    ),
    AlertRule(
        name="high_latency",
        description="High latency detected",
        severity=AlertSeverity.WARNING,
        condition="p99_latency",
        threshold=5.0,  # 5 seconds
        duration="5m",
        annotations={
            "summary": "High latency detected",
            "description": "P99 latency exceeded 5 seconds for more than 5 minutes",
        },
    ),
    AlertRule(
        name="high_memory_usage",
        description="High memory usage",
        severity=AlertSeverity.WARNING,
        condition="memory_usage_percent",
        threshold=85.0,  # 85%
        duration="10m",
        annotations={
            "summary": "High memory usage",
            "description": "Memory usage exceeded 85% for more than 10 minutes",
        },
    ),
    AlertRule(
        name="replay_lag",
        description="Replay service lag",
        severity=AlertSeverity.WARNING,
        condition="replay_lag_seconds",
        threshold=30.0,  # 30 seconds
        duration="5m",
        annotations={
            "summary": "Replay service lag detected",
            "description": "Replay service lag exceeded 30 seconds",
        },
    ),
    AlertRule(
        name="capability_exhaustion",
        description="Capability pool exhaustion",
        severity=AlertSeverity.CRITICAL,
        condition="capability_pool_available",
        threshold=0.1,  # 10% remaining
        duration="1m",
        annotations={
            "summary": "Capability pool near exhaustion",
            "description": "Less than 10% of capability pool remaining",
        },
    ),
]


def create_default_alert_manager() -> AlertManager:
    """Create an alert manager with default rules."""
    return AlertManager(rules=DEFAULT_ALERT_RULES)


class WebhookNotifier:
    """HTTP webhook notification channel."""

    def __init__(self, url: str, timeout: float = 10.0):
        self.url = url
        self.timeout = timeout

    def __call__(self, alert: Any) -> None:
        import requests
        payload = {
            "alert": {
                "rule_name": alert.rule_name,
                "severity": alert.severity,
                "message": alert.message,
                "labels": alert.labels,
                "annotations": alert.annotations,
                "starts_at": alert.starts_at.isoformat(),
                "fingerprint": alert.fingerprint,
            }
        }
        requests.post(self.url, json=payload, timeout=10)


class SlackNotifier:
    """Slack notification channel."""

    def __init__(self, webhook_url: str, channel: str = "#alerts"):
        self.webhook_url = webhook_url
        self.channel = channel

    def __call__(self, alert: Any) -> None:
        import requests

        color_map = {
            "info": "#36a64f",
            "warning": "#ff9900",
            "critical": "#ff0000",
            "emergency": "#8b0000",
        }

        payload = {
            "channel": self.channel,
            "username": "Event Horizon Alert",
            "icon_emoji": ":warning:",
            "attachments": [{
                "color": color_map.get(alert.severity, "#ff9900"),
                "title": f"[{alert.severity.upper()}] {alert.rule_name}",
                "text": alert.message,
                "fields": [
                    {"title": k, "value": v, "short": True}
                    for k, v in alert.labels.items()
                ],
                "footer": "Event Horizon",
                "ts": int(alert.starts_at.timestamp()),
            }]
        }

        requests.post(self.webhook_url, json=payload, timeout=10)


class EmailNotifier:
    """Email notification channel."""

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        username: str,
        password: str,
        from_addr: str,
        to_addrs: List[str],
        use_tls: bool = True,
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.to_addrs = to_addrs
        self.use_tls = use_tls

    def __call__(self, alert: Any) -> None:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        msg = MIMEMultipart()
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.to_addrs)
        msg["Subject"] = f"[{alert.severity.upper()}] {alert.rule_name}"

        body = f"""
Alert: {alert.rule_name}
Severity: {alert.severity}
Message: {alert.message}
Started: {alert.starts_at}
Fingerprint: {alert.fingerprint}

Labels:
{json.dumps(alert.labels, indent=2)}

Annotations:
{json.dumps(alert.annotations, indent=2)}
"""
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(self.smtp_host, self.smtp_port)
        if self.use_tls:
            server.starttls()
        server.login(self.username, self.password)
        server.sendmail(self.from_addr, self.to_addrs, msg.as_string())
        server.quit()


def create_alert_manager_with_defaults(
    notification_channels: Optional[Dict[str, Callable]] = None,
) -> AlertManager:
    """Create an alert manager with default rules and channels."""
    return AlertManager(
        rules=DEFAULT_ALERT_RULES,
        notification_channels=notification_channels or {},
    )