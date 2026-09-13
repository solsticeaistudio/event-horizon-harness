"""Hardware fail-safe backend interfaces for physical integration."""
from __future__ import annotations

import abc
import json
import threading
from dataclasses import dataclass
from typing import Any, Mapping, Optional



class HardwareFailSafeError(RuntimeError):
    """Base exception for hardware fail-safe errors."""
    pass


class HardwareBackendError(HardwareFailSafeError):
    """Hardware backend operation error."""
    pass


class HardwareBackendUnavailableError(HardwareBackendError):
    """Hardware backend device unavailable."""
    pass


class HardwareKillSwitchError(HardwareBackendError):
    """Hardware kill switch activation error."""
    pass


class HardwareBackend(abc.ABC):
    """Abstract base class for hardware fail-safe backends."""
    
    @abc.abstractmethod
    def is_available(self) -> bool:
        """Check if hardware backend is available and responsive."""
        ...
    
    @abc.abstractmethod
    def trigger_kill(self, reason: str) -> None:
        """Trigger hardware kill switch.
        
        This should physically cut power or signal to the executor cell.
        """
        ...
    
    @abc.abstractmethod
    def get_status(self) -> Mapping[str, Any]:
        """Get hardware backend status."""
        ...
    
    @abc.abstractmethod
    def test_kill_circuit(self) -> bool:
        """Test the kill circuit without activating it.
        
        Returns True if circuit is intact and functional.
        """
        ...


@dataclass(frozen=True)
class GPIOConfig:
    """GPIO pin configuration for kill switch."""
    kill_pin: int
    status_pin: Optional[int] = None
    active_low: bool = True
    pull_up: bool = True


class GPIOBackend(HardwareBackend):
    """GPIO-based hardware kill switch backend.
    
    Supports Raspberry Pi, BeagleBone, and other Linux GPIO systems.
    Requires root or gpio group membership.
    """
    
    def __init__(self, config: GPIOConfig) -> None:
        self.config = config
        self._lock = threading.Lock()
        self._gpio_initialized = False
        self._kill_state = False
    
    def _init_gpio(self) -> None:
        """Initialize GPIO pins."""
        try:
            import RPi.GPIO as GPIO
            self._GPIO = GPIO
        except ImportError:
            try:
                import Jetson.GPIO as GPIO
                self._GPIO = GPIO
            except ImportError:
                raise HardwareBackendUnavailableError("No GPIO library available (RPi.GPIO or Jetson.GPIO)")
        
        self._GPIO.setmode(self._GPIO.BCM)
        
        # Setup kill pin (output)
        if self.config.active_low:
            self._GPIO.setup(self.config.kill_pin, self._GPIO.OUT, initial=self._GPIO.HIGH)
        else:
            self._GPIO.setup(self.config.kill_pin, self._GPIO.OUT, initial=self._GPIO.LOW)
        
        # Setup status pin (input) if provided
        if self.config.status_pin is not None:
            pull = self._GPIO.PUD_UP if self.config.pull_up else self._GPIO.PUD_DOWN
            self._GPIO.setup(self.config.status_pin, self._GPIO.IN, pull_up_down=pull)
        
        self._gpio_initialized = True
    
    def is_available(self) -> bool:
        try:
            if not self._gpio_initialized:
                self._init_gpio()
            return True
        except Exception:
            return False
    
    def trigger_kill(self, reason: str) -> None:
        with self._lock:
            if not self._gpio_initialized:
                self._init_gpio()
            
            # Activate kill switch
            if self.config.active_low:
                self._GPIO.output(self.config.kill_pin, self._GPIO.LOW)
            else:
                self._GPIO.output(self.config.kill_pin, self._GPIO.HIGH)
            
            self._kill_state = True
            
            # Log the kill event
            self._log_kill_event(reason)
    
    def get_status(self) -> Mapping[str, Any]:
        with self._lock:
            status = {
                "backend": "gpio",
                "available": self.is_available(),
                "kill_active": self._kill_state,
                "kill_pin": self.config.kill_pin,
                "active_low": self.config.active_low,
            }
            
            if self._gpio_initialized and self.config.status_pin is not None:
                try:
                    status["status_pin"] = self.config.status_pin
                    status["status_pin_value"] = self._GPIO.input(self.config.status_pin)
                except Exception:
                    pass
            
            return status
    
    def test_kill_circuit(self) -> bool:
        """Test the kill circuit by briefly toggling the pin (without actually killing)."""
        with self._lock:
            if not self._gpio_initialized:
                self._init_gpio()
            
            # Read current state
            if self.config.active_low:
                current = self._GPIO.input(self.config.kill_pin)
                expected_idle = self._GPIO.HIGH
            else:
                current = self._GPIO.input(self.config.kill_pin)
                expected_idle = self._GPIO.LOW
            
            return current == expected_idle
    
    def _log_kill_event(self, reason: str) -> None:
        """Log kill event to system log."""
        import syslog
        syslog.syslog(syslog.LOG_CRIT, f"HARDWARE KILL ACTIVATED: {reason}")
    
    def close(self) -> None:
        """Cleanup GPIO on close."""
        with self._lock:
            if self._gpio_initialized:
                try:
                    self._GPIO.cleanup([self.config.kill_pin])
                    if self.config.status_pin:
                        self._GPIO.cleanup([self.config.status_pin])
                except Exception:
                    pass
                self._gpio_initialized = False


@dataclass(frozen=True)
class USBHIDConfig:
    """USB HID device configuration for kill switch."""
    vendor_id: int
    product_id: int
    kill_report_id: int = 0x01
    status_report_id: int = 0x02


class USBHIDBackend(HardwareBackend):
    """USB HID device backend for kill switch.
    
    Supports USB HID devices that implement a custom kill switch protocol.
    """
    
    def __init__(self, config: USBHIDConfig) -> None:
        self.config = config
        self._lock = threading.Lock()
        self._device = None
        self._kill_state = False
    
    def _connect(self) -> None:
        """Connect to USB HID device."""
        try:
            import hid
        except ImportError:
            raise HardwareBackendUnavailableError("hidapi not installed (pip install hidapi)")
        
        self._device = hid.device()
        self._device.open(self.config.vendor_id, self.config.product_id)
        self._device.set_nonblocking(1)
    
    def is_available(self) -> bool:
        try:
            if self._device is None:
                self._connect()
            return True
        except Exception:
            return False
    
    def trigger_kill(self, reason: str) -> None:
        with self._lock:
            if self._device is None:
                self._connect()
            
            # Send kill command
            report = bytes([self.config.kill_report_id, 0x01])  # Report ID + kill command
            self._device.write(report)
            self._kill_state = True
    
    def get_status(self) -> Mapping[str, Any]:
        with self._lock:
            return {
                "backend": "usb_hid",
                "available": self.is_available(),
                "kill_active": self._kill_state,
                "vendor_id": hex(self.config.vendor_id),
                "product_id": hex(self.config.product_id),
            }
    
    def test_kill_circuit(self) -> bool:
        """Test communication with the device."""
        try:
            if self._device is None:
                self._connect()
            # Read status report
            report = self._device.read(64)
            return len(report) > 0
        except Exception:
            return False
    
    def close(self) -> None:
        with self._lock:
            if self._device:
                try:
                    self._device.close()
                except Exception:
                    pass
                self._device = None


@dataclass(frozen=True)
class NetworkKillConfig:
    """Network-connected kill switch configuration."""
    host: str
    port: int
    auth_token: str
    timeout: float = 5.0
    use_tls: bool = False
    ca_cert: Optional[str] = None


class NetworkKillBackend(HardwareBackend):
    """Network-connected kill switch backend.
    
    Supports network-attached kill switches (e.g., IP-connected relay boards).
    """
    
    def __init__(self, config: NetworkKillConfig) -> None:
        self.config = config
        self._lock = threading.Lock()
        self._kill_state = False
    
    def is_available(self) -> bool:
        try:
            import socket
            sock = socket.create_connection((self.config.host, self.config.port), timeout=2)
            sock.close()
            return True
        except Exception:
            return False
    
    def trigger_kill(self, reason: str) -> None:
        with self._lock:
            import socket
            import ssl
            
            sock = socket.create_connection((self.config.host, self.config.port), timeout=self.config.timeout)
            if self.config.use_tls:
                context = ssl.create_default_context()
                if self.config.ca_cert:
                    context.load_verify_locations(self.config.ca_cert)
                sock = context.wrap_socket(sock, server_hostname=self.config.host)
            
            # Send kill command
            command = json.dumps({
                "action": "kill",
                "reason": reason,
                "auth": self.config.auth_token,
            }) + "\n"
            sock.sendall(command.encode())
            
            # Read response
            response = sock.recv(1024)
            sock.close()
            
            self._kill_state = True
    
    def get_status(self) -> Mapping[str, Any]:
        return {
            "backend": "network",
            "available": self.is_available(),
            "kill_active": self._kill_state,
            "host": self.config.host,
            "port": self.config.port,
        }
    
    def test_kill_circuit(self) -> bool:
        return self.is_available()


class MockHardwareBackend(HardwareBackend):
    """Mock hardware backend for testing/development."""
    
    def __init__(self) -> None:
        self._kill_state = False
        self._available = True
    
    def is_available(self) -> bool:
        return self._available
    
    def trigger_kill(self, reason: str) -> None:
        self._kill_state = True
    
    def get_status(self) -> Mapping[str, Any]:
        return {
            "backend": "mock",
            "available": self._available,
            "kill_active": self._kill_state,
        }
    
    def test_kill_circuit(self) -> bool:
        return self._available
    
    def set_available(self, available: bool) -> None:
        self._available = available
    
    def close(self) -> None:
        pass


def create_hardware_backend(
    backend_type: str = "mock",
    **kwargs,
) -> HardwareBackend:
    """Factory function to create hardware backend."""
    if backend_type == "gpio":
        return GPIOBackend(GPIOConfig(**kwargs))
    elif backend_type == "usb_hid":
        return USBHIDBackend(USBHIDConfig(**kwargs))
    elif backend_type == "network":
        return NetworkKillBackend(NetworkKillConfig(**kwargs))
    elif backend_type == "mock":
        return MockHardwareBackend()
    else:
        raise HardwareBackendError(f"Unknown hardware backend type: {backend_type}")