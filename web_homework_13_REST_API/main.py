from fastapi import FastAPI, Depends, HTTPException, Query, Request, File, UploadFile
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from contacts import models, schemas, database
from typing import List
from datetime import date, timedelta
from sqlalchemy import func
import cloudinary
from cloudinary.uploader import upload
from decouple import config
import jwt
import json
import redis
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from passlib.context import CryptContext
from email_service import send_verification_email, send_reset_password_email
from service_auth import (
    create_access_token,
    create_refresh_token,
    authenticate_user,
    get_current_user,
    generate_verification_token,
    SECRET_KEY,
    ALGORITHM,
    generate_reset_password_token,
    verify_reset_token,
)

app = FastAPI(
    title="Contacts API",
    description="API for managing contacts.",
    version="2.0.0",
)
ACCESS_TOKEN_EXPIRE_MINUTES = int(config("ACCESS_TOKEN_EXPIRE_MINUTES", default=30))
REDIS_URL = config("REDIS_URL")
redis_client = redis.StrictRedis.from_url(REDIS_URL)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


cloudinary.config(
    cloud_name=config("CLOUDINARY_CLOUD_NAME"),
    api_key=config("CLOUDINARY_API_KEY"),
    api_secret=config("CLOUDINARY_API_SECRET"),
)


origins = [config("ALLOWED_ORIGINS")]


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.post("/password-reset/")
async def request_password_reset(email: str, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="User with given email not found")

    token = generate_reset_password_token(email)
    await send_reset_password_email(email, token)

    return {"message": "Password reset link has been sent to your email."}


@app.post("/password-reset/{token}/")
async def reset_password(token: str, new_password: str, db: Session = Depends(get_db)):
    email = verify_reset_token(token)
    if not email:
        raise HTTPException(
            status_code=400, detail="Invalid token or token has expired"
        )

    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    user.hashed_password = get_password_hash(new_password)
    db.commit()

    return {"message": "Password has been reset successfully."}


@app.post("/user/update-avatar")
async def update_avatar(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    # Завантаження файлу на Cloudinary
    upload_result = upload(file.file)

    # Отримання URL завантаженого зображення
    avatar_url = upload_result.get("url")

    if avatar_url:
        # Оновлення аватара користувача в базі даних
        current_user.avatar_url = avatar_url
        db.commit()
        return {"status": "success", "avatar_url": avatar_url}

    raise HTTPException(status_code=400, detail="Failed to upload avatar")


@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    redis_client.set(
        f"user:{user.email}", json.dumps({"id": user.id, "email": user.email}), ex=3600
    )

    refresh_token = create_refresh_token(data={"sub": user.email})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token,
    }


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


@app.post("/users/", response_model=schemas.UserResponse, status_code=201)
@limiter.limit("1/minute")
async def create_user(
    request: Request, user: models.UserCreate, db: Session = Depends(get_db)
):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = get_password_hash(user.password)
    new_user = models.User(
        email=user.email, hashed_password=hashed_password, email_verified=False
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Sending verification email
    token = generate_verification_token(user.email)
    await send_verification_email(user.email, token)

    return new_user


@app.get("/verify-email/")
async def verify_email(token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")
    except jwt.JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")

    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    user.email_verified = True
    db.commit()
    return {"message": "Email verified!"}


@app.get("/contacts/birthdays/next_week")
async def get_birthdays_next_week(
    current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)
):
    today = date.today()

    next_week = today + timedelta(days=7)

    contacts = (
        db.query(models.Contact)
        .filter(
            (func.extract("month", models.Contact.birth_date) == today.month)
            & (func.extract("day", models.Contact.birth_date) >= today.day)
            & (func.extract("day", models.Contact.birth_date) <= next_week.day)
        )
        .all()
    )

    return contacts


@app.get("/contacts/search", response_model=List[schemas.Contact])
def search_contacts(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
    name: str = Query(None, description="Ім'я контакту для пошуку"),
    last_name: str = Query(None, description="Прізвище контакту для пошуку"),
    email: str = Query(None, description="Електронна адреса контакту для пошуку"),
):
    query = db.query(models.Contact).filter(models.Contact.user_id == current_user.id)

    if name:
        query = query.filter(models.Contact.first_name.contains(name))

    if last_name:
        query = query.filter(models.Contact.last_name.contains(last_name))

    if email:
        query = query.filter(models.Contact.email.contains(email))

    contacts = query.all()

    return contacts


@app.post("/contacts/", response_model=schemas.Contact)
@limiter.limit("1/minute")
def create_contact(
    request: Request,
    contact: schemas.ContactCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    db_contact = models.Contact(**contact.dict(), user_id=current_user.id)
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact


@app.get("/contacts/{contact_id}", response_model=schemas.Contact)
def read_contact(
    contact_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    db_contact = (
        db.query(models.Contact)
        .filter(
            models.Contact.id == contact_id, models.Contact.user_id == current_user.id
        )
        .first()
    )
    if db_contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    return db_contact


@app.get("/contacts/", response_model=list[schemas.Contact])
def read_contacts(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    contacts = (
        db.query(models.Contact)
        .filter(models.Contact.user_id == current_user.id)
        .offset(skip)
        .limit(limit)
        .all()
    )
    return contacts


@app.put("/contacts/{contact_id}", response_model=schemas.Contact)
def update_contact(
    contact_id: int,
    contact: schemas.ContactUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    db_contact = (
        db.query(models.Contact)
        .filter(
            models.Contact.id == contact_id, models.Contact.user_id == current_user.id
        )
        .first()
    )
    if db_contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")

    for key, value in contact.dict().items():
        setattr(db_contact, key, value)

    db.commit()
    db.refresh(db_contact)
    return db_contact


@app.delete("/contacts/{contact_id}", response_model=schemas.Contact)
def delete_contact(
    contact_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    db_contact = (
        db.query(models.Contact)
        .filter(
            models.Contact.id == contact_id, models.Contact.user_id == current_user.id
        )
        .first()
    )
    if db_contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    db.delete(db_contact)
    db.commit()
    return db_contact


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
