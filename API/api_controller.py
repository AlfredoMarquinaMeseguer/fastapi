import pprint
from datetime import datetime, timedelta
from typing import Any, List
from typing_extensions import Annotated
import bson
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from classes.dao import Offer, Petition, Permission, UserInDB
from API.api_classes import PetitionRequest, OfferQuery, TokenData
from classes.dao import User
from classes import offer_consts, mongo_conn
from classes import connect_to_users
import os

# to get a like this run:
# openssl rand -hex 32uvi
SECRET_KEY = "SECRET_KEY"
ALGORITHM = "ALGORITHM"
ACCESS_TOKEN_TIME_DAYS = "ACCESS_TOKEN_TIME_DAYS"
#
# fake_users_db = {
#     "johndoe": {
#         "username": "johndoe",
#         "full_name": "John Doe",
#         "email": "johndoe@example.com",
#         "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
#         "disabled": False,
#         "permits": []
#     }
# }

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(username: str):
    response = list(connect_to_users().find({"username": username}))
    if response:
        return UserInDB(**response[0])
    return None
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
    if user and verify_password(password, user.hashed_password):
        return user
    return False


def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=15)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, os.environ[SECRET_KEY], algorithm=os.environ.get(ALGORITHM))
    return encoded_jwt


def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
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


def get_current_active_user(
        current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def login_access_token_controller(form_data):
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


def read_own_petitions_controller(current_user):
    return_dictionary: List[Petition] = [Petition.from_mongo(i).to_api() for i in
                                         mongo_conn.connect_to_petitions().find({"user": current_user.username})]
    return return_dictionary


def create_user_controller(user, current_user):
    if Permission.ADMIN.value in current_user.permits:
        print(user)
        return user


def make_petition_controller(petition_request: PetitionRequest,
                             current_user):
    petition = Petition(**dict(petition_request),
                        creation_datetime=datetime.now(),
                        permits=[],
                        user=current_user.username)
    # Guardar en base de datos
    petition.save()
    return petition


def list_petitions_controller(current_user):
    a = mongo_conn.connect_to_petitions().find({"user": current_user.username})
    dictionary = []
    for i in a:
        _id: bson.ObjectId = i.pop("_id")
        i["id"] = _id.__str__()
        dictionary.append(i)

    return dictionary


def obtain_data_controller(petition_id: str, current_user):
    if current_user.disabled:
        return {"message": "Sorry the current user is disabled"}

    a = mongo_conn.connect_to_offers().find({offer_consts.PETITION: petition_id})

    dictionary = []
    for i in a:
        dictionary.append(Offer.from_mongo(i).to_api())

    return dictionary


def query_offers_controller(query: OfferQuery, current_user):
    # NOTE: Pa pruebas
    # Obtener info de las empresas según la petición hecha
    if current_user.disabled:
        return {"message": "Sorry the current user is disabled"}

    real: dict[str, Any] = {k: v for k, v in query.dict().items() if v is not None}
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


def get_public_ip():
    import requests
    try:
        response = requests.get('https://api.ipify.org?format=json')
        if response.status_code == 200:
            return response.json()
        else:
            print('Error: Failed to retrieve IP address.')
    except requests.exceptions.RequestException as e:
        print('Error: {}'.format(e))
