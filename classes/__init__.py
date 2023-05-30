import os
from classes.mongo_conn import connect_to_petitions, connect_to_users, connect_to_offers
import classes.offer_consts
from classes.dao import User, Petition, Offer, Source


def __init__():
    if mongo_conn.CONN not in dict(os.environ).keys():
        mongo_conn.env_from_that_config()
