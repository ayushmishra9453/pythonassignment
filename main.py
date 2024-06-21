import logging
from fastapi import FastAPI, HTTPException, Depends, status, Form
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from database import users_collection, ids_collection
from pymongo.errors import PyMongoError
from bson import ObjectId

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class User(BaseModel):
    username: str
    email: EmailStr
    password: str

class LinkID(BaseModel):
    user_email: EmailStr
    id_value: str

class OAuth2EmailRequestForm:
    def __init__(self, email: str = Form(), password: str = Form()):
        self.email = email
        self.password = password

def convert_object_ids(document):
    if isinstance(document, dict):
        return {k: (str(v) if isinstance(v, ObjectId) else convert_object_ids(v)) for k, v in document.items()}
    elif isinstance(document, list):
        return [convert_object_ids(item) for item in document]
    else:
        return document

@app.post("/register")
async def register_user(user: User):
    try:
        if users_collection.find_one({"email": user.email}):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

        hashed_password = pwd_context.hash(user.password)
        user_dict = user.dict()
        user_dict["password"] = hashed_password

        users_collection.insert_one(user_dict)
        return {"message": "User registered successfully"}

    except PyMongoError as e:
        logging.error(f"Database error: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unexpected error")

@app.post("/token")
async def login(form_data: OAuth2EmailRequestForm = Depends()):
    user = users_collection.find_one({"email": form_data.email})
    if not user or not pwd_context.verify(form_data.password, user["password"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    return {"access_token": user["email"], "token_type": "bearer"}

@app.post("/link_id")
async def link_id(link_id: LinkID):
    user = users_collection.find_one({"email": link_id.user_email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    ids_collection.insert_one({"user_email": link_id.user_email, "id_value": link_id.id_value})
    return {"message": "ID linked successfully"}

@app.get("/user_with_ids/{email}")
async def get_user_with_ids(email: str):
    try:
        user = users_collection.find_one({"email": email})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        ids = list(ids_collection.find({"user_email": email}))
        user_with_ids = {
            "user": convert_object_ids(user),
            "ids": convert_object_ids(ids)
        }
        return user_with_ids

    except PyMongoError as e:
        logging.error(f"Database error: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unexpected error")

@app.delete("/delete_user/{email}")
async def delete_user(email: str):
    try:
        user = users_collection.find_one({"email": email})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        users_collection.delete_one({"email": email})
        ids_collection.delete_many({"user_email": email})
        return {"message": "User and associated data deleted successfully"}

    except PyMongoError as e:
        logging.error(f"Database error: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unexpected error")
