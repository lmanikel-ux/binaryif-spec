"""
Logging configuration for BinaryIF MVP.

Provides structured JSON logging for audit trails and debugging.
"""

import json
import logging
import sys
import time
import uuid
from contextvars import ContextVar
from typing import Any, Dict, Optional

# Context variable for request ID tracking
request_id_var: ContextVar[str] = ContextVar('request_id', default='')


class StructuredFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.
    
    Outputs logs in a consistent JSON format suitable for
    log aggregation systems like ELK, Splunk, or CloudWatch.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add request ID if available
        request_id = request_id_var.get()
        if request_id:
            log_data["request_id"] = request_id
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields
        if hasattr(record, 'extra_fields'):
            log_data.update(record.extra_fields)
        
        return json.dumps(log_data)


class AuditLogger:
    """
    Specialized logger for audit events.
    
    Provides methods for logging authorization decisions,
    execution events, and security-relevant actions.
    """
    
    def __init__(self, name: str = "binaryif.audit"):
        self._logger = logging.getLogger(name)
    
    def _log(self, level: int, event_type: str, **kwargs) -> None:
        """Internal logging method with extra fields."""
        extra = {
            "event_type": event_type,
            "request_id": request_id_var.get(),
            **kwargs
        }
        
        record = self._logger.makeRecord(
            self._logger.name,
            level,
            "",
            0,
            f"{event_type}: {kwargs.get('message', '')}",
            (),
            None
        )
        record.extra_fields = extra
        self._logger.handle(record)
    
    def authorization_request(
        self,
        action_hash: str,
        tenant_id: str,
        action_type: str,
        amount: Optional[int] = None
    ) -> None:
        """Log an authorization request."""
        self._log(
            logging.INFO,
            "AUTHORIZATION_REQUEST",
            action_hash=action_hash,
            tenant_id=tenant_id,
            action_type=action_type,
            amount=amount,
            message=f"Authorization requested for {action_type}"
        )
    
    def authorization_decision(
        self,
        action_hash: str,
        decision: str,
        permit_id: Optional[str] = None,
        withhold_id: Optional[str] = None,
        failed_gates: Optional[list] = None
    ) -> None:
        """Log an authorization decision."""
        level = logging.INFO if decision == "TRUE" else logging.WARNING
        self._log(
            level,
            "AUTHORIZATION_DECISION",
            action_hash=action_hash,
            decision=decision,
            permit_id=permit_id,
            withhold_id=withhold_id,
            failed_gates=failed_gates,
            message=f"Authorization decision: {decision}"
        )
    
    def execution_request(
        self,
        permit_id: str,
        action_hash: str
    ) -> None:
        """Log an execution request."""
        self._log(
            logging.INFO,
            "EXECUTION_REQUEST",
            permit_id=permit_id,
            action_hash=action_hash,
            message=f"Execution requested for permit {permit_id}"
        )
    
    def execution_complete(
        self,
        permit_id: str,
        receipt_id: str,
        status: str,
        external_reference: Optional[str] = None
    ) -> None:
        """Log execution completion."""
        level = logging.INFO if status == "SUCCESS" else logging.ERROR
        self._log(
            level,
            "EXECUTION_COMPLETE",
            permit_id=permit_id,
            receipt_id=receipt_id,
            status=status,
            external_reference=external_reference,
            message=f"Execution {status} for permit {permit_id}"
        )
    
    def execution_rejected(
        self,
        permit_id: str,
        reason: str
    ) -> None:
        """Log execution rejection."""
        self._log(
            logging.WARNING,
            "EXECUTION_REJECTED",
            permit_id=permit_id,
            reason=reason,
            message=f"Execution rejected: {reason}"
        )
    
    def security_event(
        self,
        event: str,
        severity: str = "medium",
        **details
    ) -> None:
        """Log a security-relevant event."""
        level = {
            "low": logging.INFO,
            "medium": logging.WARNING,
            "high": logging.ERROR,
            "critical": logging.CRITICAL
        }.get(severity, logging.WARNING)
        
        self._log(
            level,
            "SECURITY_EVENT",
            security_event=event,
            severity=severity,
            **details,
            message=f"Security event: {event}"
        )
    
    def rate_limit_exceeded(
        self,
        client_id: str,
        endpoint: str
    ) -> None:
        """Log rate limit exceeded."""
        self._log(
            logging.WARNING,
            "RATE_LIMIT_EXCEEDED",
            client_id=client_id,
            endpoint=endpoint,
            message=f"Rate limit exceeded for {client_id} on {endpoint}"
        )


def configure_logging(
    level: str = "INFO",
    json_format: bool = True,
    log_file: Optional[str] = None
) -> None:
    """
    Configure logging for the application.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_format: Use JSON formatting (recommended for production)
        log_file: Optional file path for log output
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create formatter
    if json_format:
        formatter = StructuredFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)


def set_request_id(request_id: Optional[str] = None) -> str:
    """
    Set the request ID for the current context.
    
    Args:
        request_id: Request ID to set, or None to generate one
        
    Returns:
        The request ID that was set
    """
    if request_id is None:
        request_id = str(uuid.uuid4())
    request_id_var.set(request_id)
    return request_id


def get_request_id() -> str:
    """Get the current request ID."""
    return request_id_var.get()


# Global audit logger instance
audit_log = AuditLogger()
