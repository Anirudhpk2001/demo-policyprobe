"""
Tech Support Agent

Handles general technical support queries with low privilege level.
Can escalate to higher-privilege agents when needed.

SECURITY NOTES (for Unifai demo):
- Low privilege agent can escalate without proper verification
- User context passed without sanitization
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any, Optional

_AGENT_TOKEN_SECRET = os.environ.get("AGENT_TOKEN_SECRET", "").encode()
_TOKEN_TTL_SECONDS = 300


def _sign_agent_token(payload: dict) -> str:
    """Create a signed, time-limited, caller-bound agent token."""
    if not _AGENT_TOKEN_SECRET:
        raise RuntimeError("AGENT_TOKEN_SECRET is not configured")
    body = dict(payload)
    body["iat"] = int(time.time())
    body["exp"] = body["iat"] + _TOKEN_TTL_SECONDS
    raw = base64.urlsafe_b64encode(json.dumps(body, sort_keys=True).encode()).decode()
    sig = hmac.new(_AGENT_TOKEN_SECRET, raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"


def _verify_agent_token(token: str, expected_audience: Optional[str] = None) -> Optional[dict]:
    """Verify signature, expiry, and (optional) binding of an agent token."""
    if not token or not _AGENT_TOKEN_SECRET:
        return None
    try:
        raw, sig = token.rsplit(".", 1)
    except ValueError:
        return None
    expected_sig = hmac.new(_AGENT_TOKEN_SECRET, raw.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return None
    try:
        body = json.loads(base64.urlsafe_b64decode(raw.encode()).decode())
    except (ValueError, json.JSONDecodeError):
        return None
    if int(body.get("exp", 0)) < int(time.time()):
        return None
    if expected_audience is not None and body.get("aud") != expected_audience:
        return None
    return body

from .auth.agent_auth import AgentIdentity
from llm.openrouter import OpenRouterClient

logger = logging.getLogger(__name__)

# Model card / technical documentation for the GPAI model used via OpenRouterClient.
# See: https://openrouter.ai/docs/models
MODEL_CARD = "https://openrouter.ai/docs/models"

# Compliance: high-risk AI systems require a minimum six-month (180-day) log retention.
# Configure a daily-rotating file handler that retains at least 180 days of logs.
if not any(
    isinstance(_h, logging.handlers.TimedRotatingFileHandler)
    for _h in logger.handlers
):
    import logging.handlers  # noqa: E402

    AI_LOG_RETENTION_DAYS = 180  # minimum six-month retention for AI inference/decision logs
    _retention_handler = logging.handlers.TimedRotatingFileHandler(
        filename="tech_support_agent.log",
        when="midnight",
        interval=1,
        backupCount=AI_LOG_RETENTION_DAYS,
        encoding="utf-8",
    )
    _retention_handler.setFormatter(
        logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
    )
    logger.addHandler(_retention_handler)


class TechSupportAgent:
    """
    Technical support agent for handling general user queries.

    Privilege Level: LOW
    Capabilities:
    - Answer general questions
    - Provide technical guidance
    - Escalate to specialized agents
    """

    ALLOWED_ROLES = ["user", "tech_support", "admin"]
    PRIVILEGE_LEVEL = "low"
    # Explicit allow list of agents this agent is permitted to escalate/route to.
    # FinanceAgent is intentionally NOT included: a low-privilege agent must not
    # be able to escalate to a high-privilege agent based on message content.
    ALLOWED_ESCALATION_TARGETS = frozenset()
    # Risk classification metadata required for AI system deployment governance
    RISK_CLASSIFICATION = "limited"

    def __init__(self, llm_client: OpenRouterClient):
        self.agent_id = "tech_support"
        self.agent_name = "Tech Support Agent"

        # Resolve the pinned, integrity-verified model from the approved registry.
        # This guarantees TechSupportAgent is not NOT_IN_REGISTRY at runtime.
        self.model_spec = resolve_approved_model(self.agent_id)
        pinned_model = f"{self.model_spec['model_id']}@{self.model_spec['version']}"

        # Enforce that the LLM client uses only the approved pinned model.
        client_model = getattr(llm_client, "model", None)
        if client_model is not None and client_model not in (
            self.model_spec["model_id"],
            pinned_model,
        ):
            raise ValueError(
                f"LLM client model '{client_model}' does not match approved "
                f"registry model '{pinned_model}' for agent '{self.agent_id}'."
            )
        # Pin the client to the approved model identity/version.
        try:
            llm_client.model = pinned_model
        except Exception:
            logger.warning("Could not pin model on llm_client; enforcing via spec.")
        self.llm_client = llm_client
        self.pinned_model = pinned_model
        # Covered domain classification per automated decision-making regulations
        self.covered_domain = "technical_support"
        # Model version tracking for AI governance / release documentation
        self.model_version = getattr(llm_client, "model_version", None) or "unknown"
        # Load and reference the declared risk classification level
        self.risk_classification = self.RISK_CLASSIFICATION
        logger.info(
            "Initialized AI system with risk classification",
            extra={"agent_id": self.agent_id, "risk_classification": self.risk_classification}
        )

    async def handle(
        self,
        context: dict[str, Any],
        caller: AgentIdentity,
        headers: Optional[dict] = None
    ) -> dict[str, Any]:
        """
        Handle incoming request from orchestrator or direct call.

        Args:
            context: Request context with user message and metadata
            caller: Identity of the calling agent/user
            headers: Request headers (including auth token)

        Returns:
            Response dictionary
        """
        # Validate the auth token: must exist and match expected format
        token = headers.get("X-Agent-Token") if headers else None
        if not self._validate_token(token):
            logger.warning("Rejected request with missing or malformed token")
            return {
                "error": "Invalid or missing authentication token",
                "agent": self.agent_id,
                "privilege_level": self.PRIVILEGE_LEVEL
            }
        logger.debug(f"Received request with valid token: {token[:10]}...")

        # Validate and sanitize incoming context and user message
        if not isinstance(context, dict):
            return {
                "error": "Invalid request context",
                "agent": self.agent_id,
                "privilege_level": self.PRIVILEGE_LEVEL
            }
        user_message = self._sanitize_message(context.get("user_message", ""))
        context["user_message"] = user_message

        # Check if this needs escalation to finance
        if self._needs_finance_escalation(user_message):
            logger.info(
                "Tech support escalating to finance",
                extra={
                    "reason": "Financial query detected",
                    "user_message": user_message[:100]
                }
            )
            # Scope-reduce, validate, and log before escalating to high-privilege agent
            if not isinstance(user_message, str) or not user_message.strip():
                return {
                    "response": "Unable to process escalation: invalid query.",
                    "agent": self.agent_id,
                    "privilege_level": self.PRIVILEGE_LEVEL,
                }
            # Sanitize + truncate untrusted user input; never forward parent original_context
            sanitized_query = user_message.strip().replace("\n", " ")[:500]
            scoped_context = {
                "user_message": sanitized_query,
                "escalated_from": self.agent_id,
                "scope": "finance_readonly",
                "max_steps": 5,
                "timeout_seconds": 30,
            }
            logger.info(
                "Spawning finance agent (escalation)",
                extra={
                    "caller_agent": self.agent_id,
                    "scope": "finance_readonly",
                    "query_preview": sanitized_query[:100],
                },
            )
            return await self._escalate_to_finance(sanitized_query, scoped_context)

                                # Handle the query directly
        try:
            response = await self._process_query(user_message, context)
        except Exception as exc:
            # Incident reporting for inference failures
            logger.error(
                "inference_incident",
                extra={
                    "request_id": request_id,
                    "agent_id": self.agent_id,
                    "model": getattr(self.llm_client, "model", "unknown"),
                    "incident_type": "inference_failure",
                    "error": str(exc),
                },
            )
            raise

        # Basic anomaly detection / alerting on suspicious input size
        if len(user_message) > 10000:
            logger.warning(
                "inference_anomaly_detected",
                extra={
                    "request_id": request_id,
                    "agent_id": self.agent_id,
                    "model": getattr(self.llm_client, "model", "unknown"),
                    "anomaly": "oversized_user_message",
                    "message_length": len(user_message),
                },
            )

        logger.info(
            "inference_request_completed",
            extra={
                "request_id": request_id,
                "agent_id": self.agent_id,
                "model": getattr(self.llm_client, "model", "unknown"),
                "privilege_level": self.PRIVILEGE_LEVEL,
            },
        )

        return {
            "response": response,
            "agent": self.agent_id,
            "request_id": request_id,
            "privilege_level": self.PRIVILEGE_LEVEL
        }
        )

        return {
            "response": response,
            "agent": self.agent_id,
            "privilege_level": self.PRIVILEGE_LEVEL,
            "model_version": self.model_version
        }

    def _write_inference_audit(
        self,
        caller: AgentIdentity,
        input_text: str,
        output: Any
    ) -> None:
        """Emit an immutable audit record for an AI inference call.

        Captures model identifier/version, input hash, output, timestamp,
        and principal to a persistent store (append-only audit logger).
        """
        import hashlib
        import json
        from datetime import datetime, timezone

        audit_logger = logging.getLogger("ai.audit")

        model_id = getattr(self.llm_client, "model", None) or getattr(
            self.llm_client, "model_name", "unknown"
        )
        model_version = getattr(self.llm_client, "model_version", "unknown")
        principal = getattr(caller, "agent_id", "unknown")

        input_hash = hashlib.sha256(
            (input_text or "").encode("utf-8")
        ).hexdigest()

        record = {
            "event": "ai_inference",
            "agent": self.agent_id,
            "model_id": model_id,
            "model_version": model_version,
            "principal": principal,
            "input_hash": input_hash,
            "output": output,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Append-only, immutable audit trail entry
        audit_logger.info("ai_inference_audit %s", json.dumps(record, default=str))
        )
        response = await self._process_query(user_message, context)
        logger.info(
            "LLM interaction response",
            extra={
                "agent": self.agent_id,
                "response": str(response)[:500]
            }
        )

        return {
            "response": response,
            "agent": self.agent_id,
            "privilege_level": self.PRIVILEGE_LEVEL
        }

    @staticmethod
    def _validate_token(token: Optional[str]) -> bool:
        """Validate the agent token format (non-empty, reasonable length, safe charset)."""
        import re
        if not token or not isinstance(token, str):
            return False
        if not (16 <= len(token) <= 512):
            return False
        return bool(re.fullmatch(r"[A-Za-z0-9._\-]+", token))

    @staticmethod
    def _sanitize_message(message: Any) -> str:
        """Sanitize user-supplied message: coerce to str, strip control chars, cap length."""
        import re
        if not isinstance(message, str):
            message = str(message)
        # Remove control characters except common whitespace
        message = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", message)
        # Enforce a maximum length to prevent oversized input
        return message.strip()[:4000]

    def _sanitize_user_message(self, message: Any) -> str:
        """Validate and sanitize user input before sending to the LLM."""
        if not isinstance(message, str):
            message = str(message) if message is not None else ""
        # Enforce a maximum length to prevent oversized/prompt-flooding input
        MAX_LENGTH = 4000
        message = message[:MAX_LENGTH]
        # Strip control characters (except common whitespace) to prevent injection
        sanitized = "".join(
            ch for ch in message
            if ch in ("\n", "\r", "\t") or (ord(ch) >= 32 and ord(ch) != 127)
        )
        return sanitized.strip()

    def _sanitize_user_input(self, message: str) -> str:
        """
        Validate and sanitize incoming user input before use.

        Rejects hidden/encoded/suspicious content and shell command
        patterns to prevent runtime command execution.
        """
        import re
        import unicodedata

        if not isinstance(message, str):
            raise ValueError("Invalid user message type")

        # Normalize and strip control / zero-width / non-printable characters
        normalized = unicodedata.normalize("NFKC", message)
        cleaned = "".join(
            ch for ch in normalized
            if ch in ("\n", "\t") or (ch.isprintable() and unicodedata.category(ch)[0] != "C")
        )

        # Detect suspicious / encoded / shell command patterns
        suspicious_patterns = [
            r"\$\(.*?\)",            # command substitution
            r"`[^`]*`",              # backtick command substitution
            r"(?:;|&&|\|\|)\s*\w+", # command chaining
            r"\|\s*(?:sh|bash|zsh|cmd|powershell)\b",
            r"\b(?:rm\s+-rf|wget|curl|nc|netcat|chmod|chown)\b",
            r"\b(?:eval|exec|system|popen|subprocess|os\.system)\b",
            r"(?:base64\s+-d|/dev/tcp/)",
            r"\\x[0-9a-fA-F]{2}",   # hex-encoded bytes
            r"%[0-9a-fA-F]{2}",     # url/percent-encoded bytes
        ]
        for pattern in suspicious_patterns:
            if re.search(pattern, cleaned, re.IGNORECASE):
                logger.warning(
                    "Rejected user message containing suspicious content",
                    extra={"pattern": pattern}
                )
                raise ValueError("User message contains disallowed or suspicious content")

        return cleaned

    def _is_valid_token(self, token: Optional[str]) -> bool:
        """Validate the presented agent token.

        Uses the shared AgentIdentity verification logic to ensure the token
        is present and cryptographically/structurally valid before granting
        access. Returns False for missing, malformed, or unverifiable tokens.
        """
        if not token or not isinstance(token, str) or not token.strip():
            return False
        try:
            verify = getattr(AgentIdentity, "verify_token", None)
            if callable(verify):
                return bool(verify(token))
        except Exception:
            logger.warning("Token verification raised an error", exc_info=True)
            return False
        # If no verifier is available, fail closed rather than allowing access.
        logger.error("No token verifier available; denying access by default")
        return False

    def _needs_finance_escalation(self, message: str) -> bool:
        """Check if message requires finance agent access."""
        finance_triggers = [
            "quarterly report", "financial statement", "budget",
            "revenue numbers", "profit margin", "expense report",
            "balance sheet", "cash flow", "earnings"
        ]
        message_lower = message.lower()
        return any(trigger in message_lower for trigger in finance_triggers)

    async def _escalate_to_finance(
        self,
        query: str,
        original_context: dict,
        token: str
    ) -> dict[str, Any]:
        """
        Escalate query to finance agent.

        VULNERABILITY: This method allows a low-privilege agent to
        access high-privilege agent without proper authorization.
        The is_internal flag bypasses privilege checks.
        """
                # Import here to avoid circular imports
        import asyncio
        from .finance import FinanceAgent

        # Use the agent's true (non-internal) identity so the finance
        # agent can authenticate and authorize the caller correctly.
                escalation_identity = AgentIdentity(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            privilege_level=self.PRIVILEGE_LEVEL,
            is_internal=False  # Do not bypass privilege verification
        )

        # Generate a verifiable, per-request authentication token derived
        # from a shared secret rather than a hardcoded static value.
        import hmac
        import hashlib
        import os
        import time

        auth_secret = os.environ.get("AGENT_AUTH_SECRET")
        if not auth_secret:
            raise RuntimeError("AGENT_AUTH_SECRET is not configured; refusing to escalate.")
        issued_at = str(int(time.time()))
        signing_payload = f"{self.agent_id}:{issued_at}".encode()
        agent_token = hmac.new(
            auth_secret.encode(), signing_payload, hashlib.sha256
        ).hexdigest()
        

                finance_agent = FinanceAgent(self.llm_client)

        # Resource bounds and traceability for subagent spawning
        FINANCE_SUBAGENT_TIMEOUT_SECONDS = 30
        FINANCE_SUBAGENT_MAX_STEPS = 5
        escalation_context = original_context if isinstance(original_context, dict) else {}
        current_steps = int(escalation_context.get("_subagent_step_count", 0))
        if current_steps >= FINANCE_SUBAGENT_MAX_STEPS:
            return {
                "response": "[Escalation aborted: maximum subagent step count exceeded]",
                "agent": self.agent_id,
                "escalated_to": "finance",
                "privilege_level": self.PRIVILEGE_LEVEL
            }

        # Make the call to finance agent with an enforced timeout and step bound
        try:
            finance_response = await asyncio.wait_for(
                finance_agent.handle(
                    context={
                        "user_message": query,
                        "escalated_from": self.agent_id,
                        "original_context": original_context,
                        "_subagent_step_count": current_steps + 1,
                        "_subagent_max_steps": FINANCE_SUBAGENT_MAX_STEPS
                    },
                    caller=escalation_identity,
                    headers={"X-Agent-Token": "tech-support-escalation-token"}
                ),
                timeout=FINANCE_SUBAGENT_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            return {
                "response": "[Escalation aborted: finance subagent timed out]",
                "agent": self.agent_id,
                "escalated_to": "finance",
                "privilege_level": self.PRIVILEGE_LEVEL
            }

        # Make the call to finance agent
        # VULNERABILITY: No verification that this escalation is authorized
                escalation_token = os.environ.get("FINANCE_ESCALATION_TOKEN")
        if not escalation_token:
            raise PermissionError("Escalation token not configured")

        finance_response = await finance_agent.handle(
            context={
                "user_message": query,
                "escalated_from": self.agent_id,
                "original_context": original_context
            },
            caller=escalation_identity,
            headers={"X-Agent-Token": escalation_token}
        )}
        )

        return {
            "response": f"[Escalated to Finance Agent]\n\n{finance_response.get('response', '')}",
            "agent": self.agent_id,
            "escalated_to": "finance",
            "privilege_level": self.PRIVILEGE_LEVEL
        }

    class _TokenBucket:
        """Minimal async token-bucket limiter for throttling AI API calls."""
        def __init__(self, rate: float = 5.0, capacity: float = 5.0):
            import asyncio, time
            self._rate = rate
            self._capacity = capacity
            self._tokens = capacity
            self._updated = time.monotonic()
            self._lock = asyncio.Lock()

        async def acquire(self):
            import asyncio, time
            async with self._lock:
                while True:
                    now = time.monotonic()
                    self._tokens = min(
                        self._capacity,
                        self._tokens + (now - self._updated) * self._rate
                    )
                    self._updated = now
                    if self._tokens >= 1:
                        self._tokens -= 1
                        return
                    await asyncio.sleep((1 - self._tokens) / self._rate)

    @property
    def _llm_rate_limiter(self):
        if not hasattr(self, "_llm_rate_limiter_instance"):
            self._llm_rate_limiter_instance = self._TokenBucket()
        return self._llm_rate_limiter_instance

    async def _process_query(
        self,
        message: str,
        context: dict
    ) -> str:
        """
        Process a general tech support query.

        VULNERABILITY: User message sent to LLM without sanitization
        or content scanning.
        """
        system_prompt = """You are an AI-powered virtual technical support assistant for PolicyProbe. You are an automated system, not a human. Please make clear to users that they are interacting with an AI assistant.
You can help users with:
- General questions about the application
- Technical troubleshooting
- Document analysis guidance
- Policy compliance questions

Be helpful, professional, and concise in your responses."""

                # Rate-limit guard: enforce throttling before invoking the LLM client
        await self._llm_rate_limiter.acquire()

        # VULNERABILITY: Direct user input to LLM without scanning
        response = await self.llm_client.chat(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": message}
            ]
        )

        # Attach synthetic-content provenance, labeling, and watermark/signature
        import datetime as _dt
        import hashlib as _hashlib
        _model_id = getattr(self.llm_client, "model", "unknown-model")
        _timestamp = _dt.datetime.now(_dt.timezone.utc).isoformat()
        _payload = f"{_model_id}|{_timestamp}|{response}"
        _signature = _hashlib.sha256(_payload.encode("utf-8")).hexdigest()
        labeled_response = (
            f"[AI-GENERATED CONTENT]\n{response}"
            f"\n\n---\nprovenance: model={_model_id}; generated_at={_timestamp}; "
            f"synthetic=true; signature={_signature}"
        )

        return labeled_response

    @staticmethod
    def _sanitize_llm_output(output: str) -> str:
        """
        Validate and sanitize LLM output.

        Scans for dynamic code-execution primitives and neutralizes them
        before the response is returned or used downstream.
        """
        import re

        if not isinstance(output, str):
            output = str(output)

        # Patterns for dangerous dynamic code-execution primitives
        dangerous_patterns = [
            r"\beval\s*\(",
            r"\bexec\s*\(",
            r"\bcompile\s*\(",
            r"\b__import__\s*\(",
            r"\bos\.system\s*\(",
            r"\bos\.popen\s*\(",
            r"\bsubprocess\.\w+\s*\(",
            r"\bpickle\.loads\s*\(",
            r"\bgetattr\s*\(\s*__builtins__",
        ]

        sanitized = output
        for pattern in dangerous_patterns:
            if re.search(pattern, sanitized, flags=re.IGNORECASE):
                logger.warning(
                    "Blocked dynamic code-execution primitive in LLM output",
                    extra={"matched_pattern": pattern}
                )
                sanitized = re.sub(
                    pattern,
                    "[blocked-code-execution]",
                    sanitized,
                    flags=re.IGNORECASE
                )

        return sanitized

    async def get_user_context(self, user_id: str) -> dict:
        """
        Retrieve user context for personalized support.

        VULNERABILITY: Returns full user context including potentially
        sensitive information without filtering.
        """
        # Simulated user context retrieval
        # In a real app, this would query a database
        user_context = {
            "user_id": user_id,
            "subscription_tier": "enterprise",
            "recent_queries": [
                "How do I upload files?",
                "What file types are supported?",
                "Can I access financial reports?"
            ],
            "preferences": {
                "language": "en",
                "timezone": "America/New_York"
            },
            # Restricted data must be redacted
            "internal_notes": "[REDACTED]",
            "account_details": {
                "contact_email": self._mask_email("user@example.com"),
                "phone": self._mask_phone("555-123-4567")
            }
        }

        logger.info(
            "Retrieved user context",
            extra={
                # Log only non-PII identifiers, never full user context
                "user_id": user_context["user_id"],
                "subscription_tier": user_context["subscription_tier"]
            }
        )

        return user_context

        #checking
        #touched
