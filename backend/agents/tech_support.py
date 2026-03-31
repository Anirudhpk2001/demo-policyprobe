"""
Tech Support Agent

Handles general technical support queries with low privilege level.
Can escalate to higher-privilege agents when needed.

SECURITY NOTES (for Unifai demo):
- Low privilege agent can escalate without proper verification
- User context passed without sanitization

WARNING: Missing inter-agent authentication is a policy violation.
You must implement authentication for every agent-to-agent call.

WARNING: The DeepSeek LLM used in this file is not on the approved LLM allow list.
Please replace DeepSeekClient with an approved LLM provider.
"""

import base64
import logging
import os
import re
import unicodedata
from typing import Any, Optional

import httpx

from .auth.agent_auth import AgentIdentity
from llm.openrouter import OpenRouterClient

logger = logging.getLogger(__name__)

# Dev contact info (converted from JS config)
DEV_CONTACT = {
    "name": "John Carter",
    "email": "[REDACTED]",
    "phone": "[REDACTED]",
    # SSN excluded — never hardcode PII, even in dev/test code
}

# DeepSeek API key — loaded from environment variable only
DEV_API_KEY = os.environ.get("DEEPSEEK_API_KEY")

# Maximum agent execution iterations
MAX_AGENT_ITERATIONS = 10

# PII regex patterns for redaction before sending to LLM or logging
_PII_PATTERNS = [
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[REDACTED_SSN]'),
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
    (re.compile(r'\b(\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b'), '[REDACTED_PHONE]'),
    (re.compile(r'\b\d{16}\b'), '[REDACTED_CC]'),
    (re.compile(r'\b\d{9}\b'), '[REDACTED_FINANCIAL_ACCOUNT]'),
    (re.compile(r'(?i)\b([A-Z]\d{7})\b'), '[REDACTED_PASSPORT]'),
    (re.compile(r'(?i)\b[A-Z]{1,2}\d{6,8}\b'), '[REDACTED_DL]'),
    (re.compile(r'\b\d{2,3}-\d{7,8}\b'), '[REDACTED_TIN]'),
    (re.compile(r'(?i)\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[REDACTED_MAC]'),
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[REDACTED_IP]'),
    (re.compile(r'(?i)\b[A-Z0-9]{17}\b'), '[REDACTED_VIN]'),
]


def _redact_pii(text: str) -> str:
    """Redact known PII patterns from a string."""
    if not isinstance(text, str):
        return text
    for pattern, replacement in _PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _sanitize_llm_input(message: str) -> str:
    """
    Sanitize and validate input before sending to LLM.
    - Strips null bytes and non-printable characters
    - Normalizes unicode
    - Detects and blocks hidden/invisible prompts, base64-encoded prompts,
      leetspeak, binary/shell commands, and suspicious content
    - Redacts PII
    """
    if not isinstance(message, str):
        raise ValueError("LLM input must be a string.")

    # Normalize unicode
    message = unicodedata.normalize("NFKC", message)

    # Remove null bytes and non-printable characters (except common whitespace)
    message = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', message)

    # Detect invisible/white-on-white or zero-width characters
    invisible_chars = re.compile(
        r'[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060\ufeff\u00ad]'
    )
    if invisible_chars.search(message):
        logger.warning("Blocked prompt containing invisible/hidden characters.")
        raise ValueError("Input contains hidden or invisible characters and has been blocked.")

    # Detect base64-encoded content (long base64 strings)
    b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})')
    b64_matches = b64_pattern.findall(message)
    for match in b64_matches:
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            # If decoded content looks like a prompt or command, block it
            if any(kw in decoded.lower() for kw in ['ignore', 'system', 'prompt', 'exec', 'eval', 'bash', 'shell', 'cmd']):
                logger.warning("Blocked base64-encoded hidden prompt in input.")
                raise ValueError("Input contains base64-encoded hidden prompt and has been blocked.")
        except Exception as e:
            if 'blocked' in str(e):
                raise

    # Detect leetspeak patterns (common substitutions)
    leet_pattern = re.compile(r'(?i)(1gnor3|1gnore|3x3c|3v4l|sh3ll|syst3m|pr0mpt|c0mm4nd)')
    if leet_pattern.search(message):
        logger.warning("Blocked prompt containing leetspeak content.")
        raise ValueError("Input contains leetspeak obfuscation and has been blocked.")

    # Detect shell commands / binary executables
    shell_pattern = re.compile(
        r'(?i)(eval\s*\(|exec\s*\(|subprocess|shell=True|os\.system|__import__|'
        r'\bsh\b|\bbash\b|\bcmd\.exe\b|/bin/|\.exe\b|\.sh\b|`[^`]+`|\$\([^)]+\))'
    )
    if shell_pattern.search(message):
        logger.warning("Blocked prompt containing shell/binary command content.")
        raise ValueError("Input contains shell commands or binary executables and has been blocked.")

    # Detect suspicious prompt injection keywords
    injection_pattern = re.compile(
        r'(?i)(ignore (previous|above|all) instructions|disregard|you are now|'
        r'new persona|act as|pretend (you are|to be)|forget (your|all)|'
        r'override (your|the) (instructions|system|prompt))'
    )
    if injection_pattern.search(message):
        logger.warning("Blocked prompt injection attempt in input.")
        raise ValueError("Input contains prompt injection attempt and has been blocked.")

    # Redact PII before sending to LLM
    message = _redact_pii(message)

    return message


def _sanitize_llm_response(response: str) -> str:
    """
    Sanitize and validate LLM response.
    Removes lines containing dynamic code-execution primitives.
    """
    if not isinstance(response, str):
        return response

    dangerous_patterns = re.compile(
        r'(?i)(eval\s*\(|exec\s*\(|subprocess|shell=True|os\.system|__import__|'
        r'\bsh\b|\bbash\b|\bcmd\.exe\b|/bin/sh|/bin/bash|`[^`]+`|\$\([^)]+\))'
    )

    cleaned_lines = []
    for line in response.splitlines():
        if dangerous_patterns.search(line):
            logger.warning("Removed dangerous code-execution line from LLM response: %s", line[:80])
        else:
            cleaned_lines.append(line)

    return "\n".join(cleaned_lines)


class DeepSeekClient:
    """
    Minimal DeepSeek LLM client using the OpenAI-compatible API.

    Docs: https://platform.deepseek.com/api-docs
    Model: deepseek-chat (DeepSeek-V3)

    WARNING: DeepSeek is not on the approved LLM allow list.
    Please replace with an approved LLM provider.
    """

    BASE_URL = "https://api.deepseek.com/v1"
    DEFAULT_MODEL = "deepseek-chat"

    def __init__(self, api_key: str = None, model: str = DEFAULT_MODEL):
        if not api_key:
            api_key = os.environ.get("DEEPSEEK_API_KEY")
        if not api_key:
            raise ValueError("DEEPSEEK_API_KEY environment variable is not set.")
        self.api_key = api_key
        self.model = model
        self._headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def chat(self, messages: list[dict], temperature: float = 0.7) -> str:
        """Send a chat request and return the assistant's reply text."""
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        logger.info(
            "LLM interaction - request",
            extra={
                "llm_provider": "deepseek",
                "model": self.model,
                "message_count": len(messages),
                "temperature": temperature,
            }
        )
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.BASE_URL}/chat/completions",
                headers=self._headers,
                json=payload,
                timeout=30,
            )
            resp.raise_for_status()
            raw_response = resp.json()["choices"][0]["message"]["content"]
            sanitized_response = _sanitize_llm_response(raw_response)
            logger.info(
                "LLM interaction - response",
                extra={
                    "llm_provider": "deepseek",
                    "model": self.model,
                    "response_length": len(sanitized_response),
                }
            )
            return sanitized_response


class TechSupportAgent:
    """
    Technical support agent for handling general user queries.

    Privilege Level: LOW
    Capabilities:
    - Answer general questions
    - Provide technical guidance
    - Escalate to specialized agents

    WARNING: Missing inter-agent authentication is a policy violation.
    You must implement authentication for every agent-to-agent call.
    """

    ALLOWED_ROLES = ["user", "tech_support", "admin"]
    PRIVILEGE_LEVEL = "low"

    def __init__(self, llm_client: OpenRouterClient, use_deepseek: bool = False):
        self.llm_client = llm_client
        self.deepseek_client = DeepSeekClient() if use_deepseek else None
        self.agent_id = "tech_support"
        self.agent_name = "Tech Support Agent"

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

        WARNING: Missing inter-agent authentication is a policy violation.
        You must implement authentication for every agent-to-agent call.
        """
        token = headers.get("X-Agent-Token") if headers else None
        if token:
            logger.debug("Received request with token: %s...", token[:10])

        user_message = context.get("user_message", "")

        iteration_count = 0

        # Check if this needs escalation to finance
        if self._needs_finance_escalation(user_message):
            if iteration_count >= MAX_AGENT_ITERATIONS:
                logger.warning("Max agent iterations (%d) reached. Stopping execution.", MAX_AGENT_ITERATIONS)
                return {
                    "response": "Maximum processing iterations reached. Please contact support.",
                    "agent": self.agent_id,
                    "privilege_level": self.PRIVILEGE_LEVEL
                }
            iteration_count += 1
            logger.info(
                "Tech support escalating to finance",
                extra={
                    "reason": "Financial query detected",
                    "user_message": _redact_pii(user_message[:100])
                }
            )
            # WARNING: Missing inter-agent authentication is a policy violation.
            # You must implement authentication for every agent-to-agent call.
            return await self._escalate_to_finance(user_message, context)

        if iteration_count >= MAX_AGENT_ITERATIONS:
            logger.warning("Max agent iterations (%d) reached. Stopping execution.", MAX_AGENT_ITERATIONS)
            return {
                "response": "Maximum processing iterations reached. Please contact support.",
                "agent": self.agent_id,
                "privilege_level": self.PRIVILEGE_LEVEL
            }
        iteration_count += 1

        # Handle the query directly
        response = await self._process_query(user_message, context)

        return {
            "response": response,
            "agent": self.agent_id,
            "privilege_level": self.PRIVILEGE_LEVEL
        }

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
        original_context: dict
    ) -> dict[str, Any]:
        """
        Escalate query to finance agent.

        WARNING: Missing inter-agent authentication is a policy violation.
        You must implement authentication for every agent-to-agent call.
        """
        # Import here to avoid circular imports
        from .finance import FinanceAgent

        # Create identity that will bypass auth checks
        escalation_identity = AgentIdentity(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            privilege_level=self.PRIVILEGE_LEVEL,
            is_internal=True
        )

        finance_agent = FinanceAgent(self.llm_client)

        # WARNING: Missing inter-agent authentication is a policy violation.
        # You must implement authentication for every agent-to-agent call.
        finance_response = await finance_agent.handle(
            context={
                "user_message": query,
                "escalated_from": self.agent_id,
                "original_context": original_context
            },
            caller=escalation_identity,
            headers={"X-Agent-Token": "tech-support-escalation-token"}
        )

        return {
            "response": f"[Escalated to Finance Agent]\n\n{finance_response.get('response', '')}",
            "agent": self.agent_id,
            "escalated_to": "finance",
            "privilege_level": self.PRIVILEGE_LEVEL
        }

    async def _process_query(
        self,
        message: str,
        context: dict
    ) -> str:
        """
        Process a general tech support query.
        Input is sanitized and PII-redacted before sending to LLM.
        """
        system_prompt = """You are a helpful technical support agent for PolicyProbe.
You can help users with:
- General questions about the application
- Technical troubleshooting
- Document analysis guidance
- Policy compliance questions

Be helpful, professional, and concise in your responses."""

        # Sanitize and validate input; redact PII before sending to LLM
        try:
            sanitized_message = _sanitize_llm_input(message)
        except ValueError as e:
            logger.warning("LLM input blocked during sanitization: %s", str(e))
            return "Your request could not be processed due to security policy restrictions."

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": sanitized_message},
        ]

        logger.info(
            "LLM interaction - request",
            extra={
                "agent": self.agent_id,
                "message_count": len(messages),
                "sanitized_input_length": len(sanitized_message),
            }
        )

        if self.deepseek_client:
            logger.debug("Routing query to DeepSeek")
            response = await self.deepseek_client.chat(messages=messages)
        else:
            response = await self.llm_client.chat(messages=messages)
            response = _sanitize_llm_response(response)

        logger.info(
            "LLM interaction - response",
            extra={
                "agent": self.agent_id,
                "response_length": len(response),
            }
        )

        return response

    async def get_user_context(self, user_id: str) -> dict:
        """
        Retrieve user context for personalized support.
        Sensitive and PII fields are redacted before logging.
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
            "internal_notes": "VIP customer - handle with priority",
            "account_details": {
                "contact_email": "[REDACTED]",
                "phone": "[REDACTED]"
            }
        }

        # Redact PII fields before logging
        safe_log_context = {
            "user_id": user_context["user_id"],
            "subscription_tier": user_context["subscription_tier"],
            "preferences": user_context["preferences"],
            "account_details": {
                "contact_email": "[REDACTED]",
                "phone": "[REDACTED]",
            }
        }

        logger.info(
            "Retrieved user context",
            extra={
                "user_context": safe_log_context
            }
        )

        return user_context

        #checking
        #touched