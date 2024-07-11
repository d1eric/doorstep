from fastapi import Depends, HTTPException, status
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
#from Models.user import Staff
from Config.DB import user_collection
import random
import string
from Models.user import UserInDB, TokenData
from typing import Optional
from datetime import datetime, timedelta
from jose import jwt, JWTError
import datetime

SECRET_KEY = "yaonIwuZVHTPbCgXWjdltSOzBQifGEck"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 20



pwd_context = CryptContext(schemes=["bcrypt", "pbkdf2_sha256", "des_crypt", "argon2"], default="bcrypt")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Hash the password
def hash_password(password):
    return pwd_context.hash(password)

# Generate a random username and password
def generate_HR_credentials(firstname,lastname):
    username = f"{firstname[:2]}{lastname[:2]}{random.randint(20, 70)}"
    return username



# Generate a random username and password
def generate_buyer_credentials(firstname,lastname):
    username = f"{firstname[:2]}{lastname[:-2]}{random.randint(20, 70)}"
    return username

def generate_credentials(firstname,lastname):
    username = f"{firstname[:2]}{lastname[:-2]}{random.randint(20, 70)}"
    password = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return username, password

serial_number = 1
def generate_staff_id(firstname, lastname):
    global serial_number  # access the global serial number
    current_year = datetime.date.today().year
    last_two_digits = str(current_year)[-2:]
    current_month = str(datetime.date.today().month).zfill(2)
    staff_id = f"{firstname[:2]}{lastname[:2]}{last_two_digits}{current_month}{serial_number:03d}"
    serial_number += 1 # increment the serial number for the next username
    return staff_id
# # Send email with the credentials
# def send_email(email, username, password):
#     msg = EmailMessage()
#     msg.set_content(f'{username},{password}')

#     msg['Subject'] = 'Staff Account Credentials'
#     msg['From'] = 'mygmail@example.com'
#     msg['To'] = email

#     with smtplib.SMTP('smtp.gmail.com', 587) as server:
#         server.login('mygmail@example.com', 'gmail password')
#         server.send_message(msg)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(username: str):
    user = user_collection.find_one({"username": username})
    if user:
        return UserInDB(**user)

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                                         detail="Could Not Validate Credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credential_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credential_exception
    user = get_user(token_data.username)
    if user is None:
        raise credential_exception
    return user

async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive User")
    return current_user

