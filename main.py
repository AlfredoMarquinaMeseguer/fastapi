import pprint
from datetime import datetime, timedelta
from typing import Any
from typing_extensions import Annotated
import bson
import pymongo.cursor
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext

import classes.mongo_conn
from classes.dao import Offer, Petition, Permission, UserInDB
from API.api_classes import PetitionRequest, OfferQuery, TokenData, Token, UserRequest
from classes.dao import User
from classes import offer_consts, mongo_conn
from classes import connect_to_users
import os

# to get a like this run:
# openssl rand -hex 32uvi
SECRET_KEY = "SECRET_KEY"
ALGORITHM = "ALGORITHM"
ACCESS_TOKEN_TIME_DAYS = "ACCESS_TOKEN_TIME_DAYS"

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
        "permits": []
    }
}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(username: str):
    response = list(connect_to_users().find({"username": username}))
    if response:
        return UserInDB(**response[0])
    return False
    # # response.next()
    # # if response. == 0:
    # #     print(1)
    #
    # for i in response:
    #     print(i)
    #
    # if username in database:
    #     user_dict = database[username]
    #     return UserInDB(**user_dict)


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, os.environ[SECRET_KEY], algorithm=os.environ.get(ALGORITHM))
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, os.environ[SECRET_KEY], algorithms=[os.environ.get(ALGORITHM)])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
        current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


# Define a startup event handler
def startup_event():
    print("Executing startup event...")


# Register the startup event handler
app.add_event_handler("startup", startup_event)


# Define your API routes and other application logic...

# This code will be executed when the application starts
@app.on_event("startup")
async def startup():
    classes.mongo_conn.env_from_that_config()
    print("Application started.")


@app.post("/token", response_model=Token)
async def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(days=int(os.environ.get(ACCESS_TOKEN_TIME_DAYS)))
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/user/me/", response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user


@app.get("/user/me/items/")
async def read_own_items(current_user: Annotated[User, Depends(get_current_active_user)]):
    return [{"item_id": "Foo", "owner": current_user.username}]


@app.get("/user/me/petitions/")
async def read_own_petitions(current_user: Annotated[User, Depends(get_current_active_user)]):
    """List all the current user petitions
    :param current_user: The current active user
    :return: A list of all the petitions
    """
    return_dictionary = [i for i in mongo_conn.connect_to_petitions().find({"user": current_user.username})]

    for i in return_dictionary:  # TODO: Cambiar por Petition.to_api o algo
        i["mongo_id"] = str(i.pop("_id"))

    return return_dictionary


@app.post("/user/create")
async def create_user(user: UserRequest, current_user: Annotated[User, Depends(get_current_active_user)]):
    if Permission.ADMIN.value in current_user.permits:
        print(user)
        return user


@app.post("/petition/create")  # TODO: la func entera
async def make_petition(petition_request: PetitionRequest,
                        current_user: Annotated[User, Depends(get_current_active_user)]):
    petition = Petition(**petition_request.__dict__,
                        creation_datetime=datetime.now(),
                        permits=[],
                        user=current_user.username)
    # Guardar en base de datos
    petition.save()
    return petition


@app.get("/petition/list")
async def list_petitions(
        current_user: Annotated[User, Depends(get_current_active_user)]):
    a = mongo_conn.connect_to_petitions().find({"user": current_user.username})
    dictionary = []
    for i in a:
        _id: bson.ObjectId = i.pop("_id")
        i["id"] = _id.__str__()
        dictionary.append(i)

    return dictionary


@app.get("/offer/obtain")  # TODO: la func entera
async def obtain_data(petition_id: str,
                      current_user: Annotated[User, Depends(get_current_active_user)]):
    # NOTE: Pa pruebas
    # Obtener info de las empresas según la petición hecha
    if current_user.disabled:
        return {"message": "Sorry the current user is disabled"}

    a = mongo_conn.connect_to_offers().find({offer_consts.PETITION: petition_id})

    dictionary = []
    for i in a:
        dictionary.append(Offer.from_mongo(i).to_api())

    return dictionary


@app.post("/offer/query")  # TODO: la func entera
async def query_offers(query: OfferQuery,
                       current_user: Annotated[User, Depends(get_current_active_user)]):
    # NOTE: Pa pruebas
    # Obtener info de las empresas según la petición hecha
    if current_user.disabled:
        return {"message": "Sorry the current user is disabled"}

    # { key:value for (key,value) in dict.items() if condition }
    real: dict[str, Any] = {k: v for k, v in query.dict().items() if v is not None}
    # for k, v in query.dict().items():
    #     if v is not None:
    #         real[k] = v

    return_offers = []
    offer_conn = mongo_conn.connect_to_offers()
    if real.get(offer_consts.PETITION) is None:
        b = mongo_conn.connect_to_petitions().find({"user": current_user.username})
        user_petitions = [i["_id"] for i in b]
        for petition in user_petitions:
            real.update({offer_consts.PETITION: petition})
            return_offers.extend(
                [Offer.from_mongo(offer).to_api() for offer in offer_conn.find(real)]
            )
    else:
        return_offers.extend(
            [Offer.from_mongo(offer).to_api() for offer in offer_conn.find(real)]
        )

    return return_offers
