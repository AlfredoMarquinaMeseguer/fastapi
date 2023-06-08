from typing import List
from typing_extensions import Annotated
from fastapi import Depends, FastAPI
from fastapi.security import OAuth2PasswordRequestForm
import classes.mongo_conn
from API.api_controller import login_access_token_controller, get_current_active_user, read_own_petitions_controller, \
    make_petition_controller, create_user_controller, list_petitions_controller, obtain_data_controller, \
    query_offers_controller
from API.api_classes import PetitionRequest, OfferQuery, Token, UserRequest
from classes.dao import User, Petition, Offer

app = FastAPI()


# Define a startup event handler
def startup_event():
    print("Executing startup event...")


# Register the startup event handler
app.add_event_handler("startup", startup_event)


# This code will be executed when the application starts
@app.on_event("startup")
async def startup():
    classes.mongo_conn.env_from_that_config()
    print("Application started.")


@app.get("/", response_model=dict)
async def sorry():
    return {"mensaje": "Perdona, pero aquí no hay API. Por favor ve a la pestaña docs o redocs para tener aceso a "
                       "todas la funciones.",
            "message": "Sorry, there is no API here. Please go to docs or redocs to have access to all the functions.",
            }


@app.post("/token", response_model=Token)
async def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    return login_access_token_controller(form_data)


@app.get("/user/me", response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    """
    List the information of the current activa user.
    :param current_user: The token
    :return: User information
    """
    return current_user


@app.get("/user/me/petitions")
async def read_own_petitions(current_user: Annotated[User, Depends(get_current_active_user)]):
    """List all the current user petitions
    :param current_user: The current active user
    :return: A list of all the petitions
    """
    return read_own_petitions_controller(current_user)


@app.post("/user/create")
async def create_user(user: UserRequest, current_user: Annotated[User, Depends(get_current_active_user)]):
    return create_user_controller(user, current_user)


@app.post("/petition/create")
async def make_petition(petition_request: PetitionRequest,
                        current_user: Annotated[User, Depends(get_current_active_user)]):
    return make_petition_controller(petition_request, current_user)


@app.get("/petition/list")
async def list_petitions(current_user: Annotated[User, Depends(get_current_active_user)]):
    return list_petitions_controller(current_user)


@app.get("/offer/obtain")
async def obtain_data(petition_id: str,
                      current_user: Annotated[User, Depends(get_current_active_user)]):
    """ Obtains a list of all the offers from the given `petition_id` if it belongs to this user

    :param petition_id:
    :param current_user:
    :return:
    """
    return obtain_data_controller(petition_id, current_user)


@app.post("/offer/query", response_model=list[Offer])
async def query_offers(query: OfferQuery,
                       current_user: Annotated[User, Depends(get_current_active_user)]):
    return query_offers_controller(query, current_user)


@app.get("/ip")
async def ip():
    import requests
    return requests.get('https://api.ipify.org?format=json').json()
