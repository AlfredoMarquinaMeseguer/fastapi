import configparser
import enum
import os
import pprint

import pymongo

CONN = 'MONGO_CONN'
DB = 'MONGO_DATABASE'


class AvailableCollection(enum.Enum):
    # Each value is the name of the environment variable that is supposed to have this shit stored
    OFFERS = 'OFFERS_COLLECTION'
    PETITIONS = 'PETITIONS_COLLECTION'
    USERS = 'USERS_COLLECTION'


POSSIBLE_PATHS = ["conf/config.ini", "classes/conf/config.ini", "final_scraper/classes/conf/config.ini"]


# TODO: currently using this one, Change to the environ one.
def obtain_collection_file(selected_collection: AvailableCollection) -> pymongo.collection.Collection:
    """
    Obtains a mongo collection made from options in the fiel config.ini.
    :param selected_collection: Indicates collections to use.
    :return: The PyMongo collections you where searching for.
    """

    config = configparser.ConfigParser()

    num = 0
    while num < len(POSSIBLE_PATHS) and len(config.items()) == 1:  # I honestly don't know which one is the correct one
        config.read(POSSIBLE_PATHS[num])
        num += 1
    del num

    # config.read("/home/alfredo/Documents/GitHub/ProyectoFinalDAM/Job_scraper/const_and_utils/config.ini")
    mongo_connection = config.get('ATLAS', 'MONGO_CONN')
    db = config.get('database', 'DB')
    collection = config.get('database', selected_collection.value)

    return pymongo.MongoClient(mongo_connection)[db][collection]


def obtain_collection_environ(collection: AvailableCollection) -> pymongo.collection.Collection:
    """
    Obtains a mongo collection made from options in the environments variables.
    :param collection: Indicates collections to use.
    :return: The PyMongo collections you where searching for.
    """
    import os
    mongo_connection = os.environ.get(CONN)
    db = os.environ.get(DB)
    return pymongo.MongoClient(mongo_connection)[db][collection.value]


def connect_to_offers() -> pymongo.collection.Collection:
    return obtain_collection_file(AvailableCollection.OFFERS)


def connect_to_users() -> pymongo.collection.Collection:
    return obtain_collection_file(AvailableCollection.USERS)


def connect_to_petitions() -> pymongo.collection.Collection:
    return obtain_collection_file(AvailableCollection.PETITIONS)


def update_env_from_file(file_path):
    with open(file_path, "r") as file:
        lines = file.readlines()
        for line in lines:
            line = line.strip()
            if line and not line.startswith(("#", "[", "\n")):
                position = line.find("=")
                os.environ[line[:position]] = line[position + 1:]


def env_from_that_config():
    for file in POSSIBLE_PATHS:
        try:
            print(file)
            update_env_from_file(file)
            break
        except FileNotFoundError:
            continue


if __name__ == "__main__":
    # env_from_that_config()
    # pprint.pprint(dict(os.environ))

    a = connect_to_users().find()
    for i in a:
        pprint.pprint(i)
    # print([itr for itr in connect_to_petitions().find()])
