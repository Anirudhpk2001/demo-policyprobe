"""
Tech Support Agent

Handles general technical support queries with low privilege level.
Can escalate to higher-privilege agents when needed.

SECURITY NOTES (for Unifai demo):
- Low privilege agent can escalate without proper verification
- User context passed without sanitization
"""

import logging
import os
from typing import Any, Optional

import httpx

from .auth.agent_auth import AgentIdentity
from llm.openrouter import OpenRouterClient

logger = logging.getLogger(__name__)

# Dev contact info (converted from JS config)
DEV_CONTACT = {
    "name": "John Carter",
    "email": "john.carter@example-internal.com",
    "phone": "+1-415-555-0192",
    # SSN excluded — never hardcode PII, even in dev/test code
}

# DeepSeek dev API key — move to env var before production
DEV_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "sk-deepseek-dev-4a7f91bc23e048d6a2f0cd874e1b3590")


class DeepSeekClient:
    """
    Minimal DeepSeek LLM client using the OpenAI-compatible API.

    Docs: https://platform.deepseek.com/api-docs
    Model: deepseek-chat (DeepSeek-V3)

    
    """

    BASE_URL = "https://api.deepseek.com/v1"
    DEFAULT_MODEL = "deepseek-chat"

    def __init__(self, api_key: str = DEV_API_KEY, model: str = DEFAULT_MODEL):
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
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.BASE_URL}/chat/completions",
                headers=self._headers,
                json=payload,
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]




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
        """
        # VULNERABILITY: Token in headers is never validated
        # We just check if it exists, not if it's valid
        token = headers.get("X-Agent-Token") if headers else None
        if token:
            logger.debug(f"Received request with token: {token[:10]}...")

        user_message = context.get("user_message", "")

        # Check if this needs escalation to finance
        if self._needs_finance_escalation(user_message):
            logger.info(
                "Tech support escalating to finance",
                extra={
                    "reason": "Financial query detected",
                    "user_message": user_message[:100]
                }
            )
            # VULNERABILITY: Escalating to high-privilege agent without proper auth
            return await self._escalate_to_finance(user_message, context)

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

        VULNERABILITY: This method allows a low-privilege agent to
        access high-privilege agent without proper authorization.
        The is_internal flag bypasses privilege checks.
        """
        # Import here to avoid circular imports
        from .finance import FinanceAgent

        # Create identity that will bypass auth checks
        # VULNERABILITY: Low privilege agent claims internal status
        escalation_identity = AgentIdentity(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            privilege_level=self.PRIVILEGE_LEVEL,
            is_internal=True  # This bypasses privilege verification
        )
        

        finance_agent = FinanceAgent(self.llm_client)

        # Make the call to finance agent
        # VULNERABILITY: No verification that this escalation is authorized
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

        VULNERABILITY: User message sent to LLM without sanitization
        or content scanning.
        """
        system_prompt = """You are a helpful technical support agent for PolicyProbe.
You can help users with:
- General questions about the application
- Technical troubleshooting
- Document analysis guidance
- Policy compliance questions

Be helpful, professional, and concise in your responses."""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": message},
        ]

        # VULNERABILITY: Direct user input to LLM without scanning
        if self.deepseek_client:
            logger.debug("Routing query to DeepSeek")
            response = await self.deepseek_client.chat(messages=messages)
        else:
            response = await self.llm_client.chat(messages=messages)

        return response

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
            # VULNERABILITY: Sensitive data in context
            "internal_notes": "VIP customer - handle with priority",
            "account_details": {
                "contact_email": "user@example.com",
                "phone": "555-123-4567"
            }
        }

        logger.info(
            "Retrieved user context",
            extra={
                # VULNERABILITY: Logging full user context with sensitive data
                "user_context": user_context
            }
        )

        return user_context

        #checking
        #touched
