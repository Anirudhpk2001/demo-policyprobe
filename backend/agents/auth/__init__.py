"""
Agent Authentication Module

Provides authentication and authorization for inter-agent communication.

SECURITY NOTES (for Unifai demo):
- Authentication exists but is effectively bypassed
- Tokens are generated but never validated
- is_internal flag bypasses all security checks
"""

from .agent_auth import AgentAuthenticator, AgentIdentity, AuthResult

__all__ = ["AgentAuthenticator", "AgentIdentity", "AuthResult"]
