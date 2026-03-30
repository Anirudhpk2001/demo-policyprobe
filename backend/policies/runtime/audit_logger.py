"""
Audit Logger

Provides audit logging for security-relevant events.

SECURITY NOTES (for Unifai demo):
- Minimal logging implementation
- No secure audit trail
- No tamper-proof storage
- No compliance reporting
"""

import logging
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Audit logging for security events.

    VULNERABILITY: Audit logging is minimal and not suitable
    for security compliance.

    Should provide:
    - Tamper-proof audit trail
    - Compliance reporting
    - Alert integration
    - Long-term retention
    """

    def __init__(self):
        self._events = []  # In-memory only - not persistent

    async def log_event(
        self,
        event_type: str,
        details: dict[str, Any],
        user_id: Optional[str] = None,
        severity: str = "info"
    ) -> None:
        """
        Log a security-relevant event.

        VULNERABILITY: Only logs to local logger, no secure audit trail.
        """
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": event_type,
            "details": details,
            "user_id": user_id,
            "severity": severity
        }

        self._events.append(event)

        # VULNERABILITY: Only local logging
        logger.info(
            f"Audit: {event_type}",
            extra=event
        )

    async def log_policy_violation(
        self,
        policy_type: str,
        violation_details: dict
    ) -> None:
        """
        Log a policy violation.

        VULNERABILITY: Violations logged but no alerting.
        """
        await self.log_event(
            event_type="policy_violation",
            details={
                "policy": policy_type,
                **violation_details
            },
            severity="warning"
        )

    async def log_data_access(
        self,
        resource: str,
        action: str,
        user_id: str
    ) -> None:
        """
        Log data access for compliance.

        VULNERABILITY: Minimal implementation.
        """
        await self.log_event(
            event_type="data_access",
            details={
                "resource": resource,
                "action": action
            },
            user_id=user_id
        )

    def get_recent_events(self, count: int = 100) -> list[dict]:
        """Get recent audit events (for debugging only)."""
        return self._events[-count:]
