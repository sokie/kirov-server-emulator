import secrets

from cachetools import TTLCache

# Create a session store that can hold up to 1024 sessions,
# with each session lasting for 3600 seconds (1 hour).
# After 1 hour of being created, a session will be automatically removed.
session_store = TTLCache(maxsize=1024, ttl=3600)


def create_session(user_data):
    """
    Creates a new user session and stores it in the cache.

    Args:
        user_data (dict): A dictionary containing user information.

    Returns:
        str: A unique session ID.
    """
    session_id = secrets.token_hex(16)
    session_store[session_id] = user_data
    print(f"Session created for user: {user_data.get('username')}. Session ID: {session_id}")
    return session_id


def get_session(session_id):
    """
    Retrieves a user session from the cache.

    Args:
        session_id (str): The session ID to look up.

    Returns:
        dict or None: The user data if the session is valid, otherwise None.
    """
    return session_store.get(session_id)


def delete_session(session_id):
    """
    Deletes a user session from the cache.

    Args:
        session_id (str): The session ID to delete.
    """
    if session_id in session_store:
        del session_store[session_id]
        print(f"Session {session_id} deleted.")
    else:
        print(f"Session {session_id} not found or already expired.")
