import asyncio
from typing import Dict, Optional

from app.util.logging_helper import get_logger

logger = get_logger(__name__)


class SessionManager:
    def __init__(self):
        # Maps sesskey -> protocol_instance
        self.active_users: Dict[str, asyncio.Protocol] = {}
        # Maps persona_id -> protocol_instance (for buddy lookups)
        self.users_by_persona: Dict[int, asyncio.Protocol] = {}
        logger.debug("Session Manager initialized")

    def register_user(self, sesskey: str, protocol_instance: asyncio.Protocol):
        """Registers a user's protocol instance upon successful login."""
        self.active_users[sesskey] = protocol_instance

        # Also register by persona_id if available
        if hasattr(protocol_instance, 'persona_id') and protocol_instance.persona_id:
            self.users_by_persona[protocol_instance.persona_id] = protocol_instance

        logger.debug("User '%s' registered. Total active users: %d", sesskey, len(self.active_users))

    def unregister_user(self, sesskey: str):
        """Unregisters a user, typically on disconnect."""
        protocol_instance = self.active_users.get(sesskey)
        if protocol_instance:
            # Remove from persona mapping
            if hasattr(protocol_instance, 'persona_id') and protocol_instance.persona_id:
                self.users_by_persona.pop(protocol_instance.persona_id, None)

            del self.active_users[sesskey]
            logger.debug("User '%s' unregistered. Total active users: %d", sesskey, len(self.active_users))

    def get_user_by_persona_id(self, persona_id: int) -> Optional[asyncio.Protocol]:
        """Gets a user's protocol instance by their persona ID."""
        return self.users_by_persona.get(persona_id)

    def is_user_online(self, persona_id: int) -> bool:
        """Checks if a user is online by their persona ID."""
        return persona_id in self.users_by_persona

    async def send_to_user(self, sesskey: str, message: str) -> bool:
        """Sends a message to a specific user if they are online."""
        protocol_instance = self.active_users.get(sesskey)
        if protocol_instance:
            # The transport object is used to write data to the socket
            protocol_instance.transport.write(message.encode("utf-8"))
            logger.debug("Sent message to '%s': %s", sesskey, message.strip())
            return True
        else:
            logger.debug("Failed to send message: User '%s' not found.", sesskey)
            return False

    async def send_to_persona(self, persona_id: int, message: str) -> bool:
        """Sends a message to a user by their persona ID."""
        protocol_instance = self.users_by_persona.get(persona_id)
        if protocol_instance and hasattr(protocol_instance, 'transport'):
            protocol_instance.transport.write(message.encode("utf-8"))
            return True
        return False
