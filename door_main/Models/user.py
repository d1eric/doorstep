from pydantic import BaseModel
from typing import Optional


class Staff(BaseModel):
    first_name: str
    last_name: str
    username : str
    email: str
    phone_number: str
    job_title: str
    role : str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class UserInDB(Staff):
    hashed_password: str
    staff_id : str
    job_title : Optional[str] = None
