"""
Web Authentication - Session-based authentication for web portal.

Provides session management utilities for user login/logout on the web portal.
"""

import secrets
from datetime import datetime

from fastapi import Depends, Request, Response
from sqlmodel import Session, select

from app.db.database import get_session
from app.models.models import User, WebSession

SESSION_COOKIE_NAME = "ra3_session"
SESSION_TOKEN_LENGTH = 32


def generate_session_token() -> str:
    """Generate a secure random session token."""
    return secrets.token_urlsafe(SESSION_TOKEN_LENGTH)


def create_web_session(db: Session, user_id: int) -> WebSession:
    """
    Create a new web session for a user.

    Args:
        db: Database session
        user_id: User ID

    Returns:
        Created WebSession
    """
    session_token = generate_session_token()
    web_session = WebSession(
        session_token=session_token,
        user_id=user_id,
        is_active=True,
    )
    db.add(web_session)
    db.commit()
    db.refresh(web_session)
    return web_session


def get_web_session_by_token(db: Session, token: str) -> WebSession | None:
    """
    Get an active web session by token.

    Args:
        db: Database session
        token: Session token

    Returns:
        WebSession if valid, None otherwise
    """
    stmt = select(WebSession).where(
        WebSession.session_token == token,
        WebSession.is_active == True,
        WebSession.expires_at > datetime.utcnow(),
    )
    return db.exec(stmt).first()


def invalidate_web_session(db: Session, token: str) -> bool:
    """
    Invalidate a web session (logout).

    Args:
        db: Database session
        token: Session token

    Returns:
        True if session was invalidated, False if not found
    """
    web_session = get_web_session_by_token(db, token)
    if web_session:
        web_session.is_active = False
        db.add(web_session)
        db.commit()
        return True
    return False


def get_user_from_session(db: Session, token: str) -> User | None:
    """
    Get the user associated with a session token.

    Args:
        db: Database session
        token: Session token

    Returns:
        User if session valid, None otherwise
    """
    web_session = get_web_session_by_token(db, token)
    if web_session:
        return db.get(User, web_session.user_id)
    return None


def set_session_cookie(response: Response, session_token: str) -> None:
    """
    Set the session cookie on a response.

    Args:
        response: FastAPI Response object
        session_token: Session token to set
    """
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 24 * 7,  # 7 days
    )


def clear_session_cookie(response: Response) -> None:
    """
    Clear the session cookie from a response.

    Args:
        response: FastAPI Response object
    """
    response.delete_cookie(key=SESSION_COOKIE_NAME)


async def get_current_user_optional(
    request: Request,
    db: Session = Depends(get_session),
) -> User | None:
    """
    Dependency that returns the current user or None.

    Use this for pages that can be viewed by both logged-in and anonymous users.
    """
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_token:
        return None
    return get_user_from_session(db, session_token)


async def get_current_user_required(
    user: User | None = Depends(get_current_user_optional),
) -> User:
    """
    Dependency that requires a logged-in user.

    Use this for pages that require authentication.
    Raises an exception if not logged in.
    """
    if user is None:
        from fastapi import HTTPException, status

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return user
