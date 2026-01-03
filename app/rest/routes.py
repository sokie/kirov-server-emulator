from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session

from app.db.crud import create_new_user, get_user_by_username
from app.db.database import get_session
from app.models.models import UserCreate, UserLogin, UserPublic
from app.security import verify_password

# The router prefix will be /api/rest, so these endpoints will be
# /api/rest/users/register and /api/rest/users/login
router = APIRouter(prefix="/users", tags=["Users"])


@router.post("/register", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
async def register_new_user(user_in: UserCreate, session: Session = Depends(get_session)):
    """
    Register a new user, now storing them in the SQLite database.
    """
    existing_user = get_user_by_username(session=session, username=user_in.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered.",
        )

    created_user = create_new_user(session=session, user_create=user_in)
    return created_user


@router.post("/login")
async def login_for_access(user_in: UserLogin, session: Session = Depends(get_session)):
    """
    Authenticate a user against the database.
    """
    user = get_user_by_username(session=session, username=user_in.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    if not verify_password(user_in.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {"message": f"Login successful for user: {user.username}"}


@router.get("/items")
async def read_items():
    return [{"name": "Item Foo"}, {"name": "Item Bar"}]


@router.get("/items/{item_id}")
async def read_item(item_id: int):
    return {"item_id": item_id, "name": f"Item {item_id}"}
