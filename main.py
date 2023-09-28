from datetime import datetime, timedelta

from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from pydantic import BaseModel
from passlib.context import CryptContext

from jose import jwt, JWTError

SECRET_KEY = "860d6e04e8f41dab4e1bccb49a87103813f9e07fb0b56e6f8ef6792a6a011f33"
ALGORITHM = "HS256"


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def create_token(data: dict, time_expires: datetime | None = None):
    data_copy = data.copy()
    if time_expires is None:
        expires = datetime.utcnow() + timedelta(minutes=15)
    else:
        expires = datetime.utcnow() + time_expires

    data_copy.update({"exp": expires})

    token_jwt = jwt.encode(data_copy, key=SECRET_KEY, algorithm=ALGORITHM)

    return token_jwt


def fake_hash_password(password: str):
    return "fakehashed" + password


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)
    return []


def verify_password(plane_password, hashed_password):
    return pwd_context.verify(plane_password, hashed_password)


def authenticate_user(db, username, password):
    user = get_user(db, username)

    if not (user and verify_password(password, user.hashed_password)):
        raise HTTPException(
            status_code=401, detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return user


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, key=SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception

        token_data = TokenData(username=username)

    except JWTError:
        raise credentials_exception

    user = get_user(fake_users_db, username=token_data.username)

    if user is None:
        raise credentials_exception

    return user


async def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.get("/")
async def root():
    return "Hola mundo!!"


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user


@app.post("/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):

    user = authenticate_user(
        fake_users_db,
        form_data.username,
        form_data.password
    )

    access_token_expires = timedelta(minutes=30)
    access_token_jwt = create_token(
        {"sub": user.username},
        access_token_expires
    )

    return {"access_token": access_token_jwt, "token_type": "bearer"}
