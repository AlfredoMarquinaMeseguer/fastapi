"""
Contains all the classes for the MongoDB of the Job Scraper project.
Offer:
    Contains ways to create a
"""
import copy
import datetime
import re
from typing import Any

import pymongo
from datetime import date
import bson
from pydantic import BaseModel
from dateutil import parser
import enum

from classes import mongo_conn, connect_to_users

API_VALID_TYPES = (bool, bytes, float, int, str)


def to_api(x: Any) -> dict:
    """
    Transform an object that can be converted to dictionary into an acceptable API format with the types and stuff.
    :param x: object with dictionary form.
    :return: API format dictionary.
    """
    return_dict: dict = {}
    for key, value in dict(x).items():
        # Ignore the ObjectId because we don't want THEM to know...
        if value is not None and not isinstance(value, ObjectId):
            if isinstance(value, API_VALID_TYPES):
                return_dict[key]: dict[str: any] = __api_format__(value)
            elif isinstance(value, enum.Enum):  # for enums
                return_dict[key]: dict[str: str] = __api_format__(value.value)
            else:
                return_dict[key]: dict[str: str] = __api_format__(str(value))
    return return_dict


def __api_format__(value: any) -> dict[str, dict[str, Any]]:
    # TODO: finish doc
    """
    The format for each value of the resulting API format dictionary.
    :param value:
    :return:
    """
    return {"value": value, "type": type(value).__name__}


class Source(enum.Enum):
    INFO_JOBS = "InfoJobs.net"
    TALENT = "talent.com"
    INFO_EMPLEO = "InfoEmpleo.com"
    WE_HIRING = "www.wearehiring.io"
    TECNO_EMPLEO = "www.tecnompleo.com"


class ObjectId(bson.ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not isinstance(v, bson.ObjectId):
            raise TypeError('ObjectId required')
        return str(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type="string", example="[64734d91e49a37d85c833af7, 64734d9c9994f1d8b1c0f7a0)")


# *************  Convert salary string to int ************* #
def salary_to_int(salary: str) -> int:
    return int(re.sub('[.€$, ]', '', salary)) if len(salary) else None


# TODO: mover constantes
#  puede que no necesarias
LOGO_URL_IJ = 'logoUrl'
URI_IJ = 'uri'
LINK_IJ = 'link'
REQUIREMENT_MIN_IJ = 'requirementMin'
EXPERIENCE_MIN_IJ = 'experienceMin'
STUDIES_IJ = 'study'
SALARY_PERIOD_IJ = 'salaryPeriod'
SALARY_MAX_IJ = 'salaryMax'
SALARY_MIN_IJ = 'salaryMin'
WORK_DAY_IJ = 'workDay'
CONTRACT_TYPE_IJ = 'contractType'
SUBCATEGORY_IJ = 'subcategory'
CATEGORY_IJ = 'category'
COMPANY_IJ = 'author'
NAME = 'name'
CITY_IJ = 'city'
VALUE = 'value'
PROVINCE_IJ = 'province'
TITLE_IJ = 'title'

ID_IJ = 'id'

UPDATED = 'updated'
PUBLISHED = 'published'


class Offer(BaseModel):
    # ************* Constants *************
    SCHEMA = '__annotations__'
    SCHEMA_WRONG_TYPE_MESSAGE = 'The element with key {} is not an instance of {} is and instance of {}. Fix that'
    SCHEMA_WRONG_KEY_MESSAGE = "Key {} not in schema keys: {}"
    # ************* Attributes *************
    mongo_id: ObjectId | None = None  # ID in mongo db
    id: str | None = None  # ID in source db
    petition_id: ObjectId | None = None
    source: Source | None = None  # Page form where the printable comes
    title: str | None = None  # Relevant information
    company: str | None = None
    province: str | None = None  # Place
    city: str | None = None
    category: str | None = None  # Category
    subcategory: str | None = None
    post_date: date | None = None  # Dates
    update_date: date | None = None
    add_date: date | None = None
    contract_type: str | None = None
    workday: str | None = None
    salary_min: int | None = None  # Salary
    salary_max: int | None = None
    salary_period: str | None = None
    studies: str | None = None  # Requirements
    experience_min: str | None = None
    requirement_min: str | None = None
    description: str | None = None
    link_job: str | None = None  # Links
    link_company: str | None = None
    # NOTE: This is to show the image in the graphical interface
    # RIP graphic interface
    link_logo: str | None = None

    # ***************************************  Static Methods *************************************** #
    @staticmethod
    def _api_format(value: any, value_type: str) -> dict[str:str]:
        return {"value": value, "type": value_type}

    # ************************************  Class methods for Input dictionaries ************************************ #
    @classmethod
    def from_mongo(cls, data: dict):
        data["mongo_id"] = data.pop("_id")
        return cls(**data)

    @classmethod
    def from_mongo_collection(cls, query: dict, collection: pymongo.collection.Collection):
        """Creates a list of Job objects from a

        :param query:
        :param collection:
        :return:
        """
        pass

    @classmethod
    def from_infojobs(cls, data: dict):
        return cls(id=data.get(ID_IJ),
                   source=Source.INFO_JOBS,  # source
                   title=data.get(TITLE_IJ),
                   province=data.get(PROVINCE_IJ).get(VALUE),
                   city=data.get(CITY_IJ),
                   company=data.get(COMPANY_IJ).get(NAME),
                   category=data.get(CATEGORY_IJ).get(VALUE),
                   subcategory=data.get(SUBCATEGORY_IJ).get(VALUE),
                   post_date=parser.isoparse(data.get(PUBLISHED)).date(),
                   update_date=parser.isoparse(data.get(UPDATED)).date(),
                   add_date=date.today(),
                   contract_type=data.get(CONTRACT_TYPE_IJ).get(VALUE),
                   workday=data.get(WORK_DAY_IJ).get(VALUE),
                   salary_min=salary_to_int(
                       data.get(SALARY_MIN_IJ).get(VALUE)),  # Salario
                   salary_max=salary_to_int(data.get(SALARY_MAX_IJ).get(VALUE)),
                   salary_period=data.get(SALARY_PERIOD_IJ).get(VALUE),
                   studies=data.get(STUDIES_IJ).get(VALUE),  # Requerimientos
                   experience_min=data.get(EXPERIENCE_MIN_IJ).get(VALUE),
                   requirement_min=data.get(REQUIREMENT_MIN_IJ),
                   link_job=data.get(LINK_IJ),  # Links
                   link_company=data.get(COMPANY_IJ).get(URI_IJ),
                   link_logo=data.get('author').get(LOGO_URL_IJ)
                   )

    @classmethod
    def from_talent(cls, data=None):
        if data is None:
            data = {}

        return cls(**data, source=Source.TALENT)

    @classmethod
    def from_scrapped_safe(cls, data: dict[str, str | datetime.date | int], source: Source):
        """Like from_scrapped, but you make sure the types of `data` are correct, or it raises error.

        :param data:
        :param source:
        :return:
        """
        not_malformed, errors = Offer.validate_input(data)
        if not not_malformed:
            message = "This are error you had: {}".format(errors)
            raise TypeError(message)

        return cls.from_scrapped(data, source)

    @classmethod
    def from_scrapped(cls, data: dict[str, str | datetime.date | int], source: Source,
                      petition: ObjectId | None = None):
        """
        Creates an object from `data`, considering it comes from the source `source`. Quick guide to erros:
        - KeyError: dictionary `data` malformed
        - TypeError: source not in enum Source or not supported yet
        :param data: dictionary of the data for the object. The keys have to
        :param source: enum that represents which page it comes from
        :param petition: mongo id of the petition for scraping
        :return: A job object well-formed or an error
        """

        match source:
            case Source.INFO_JOBS:
                return_value = cls.from_infojobs(data)
            case Source.TALENT | Source.INFO_EMPLEO | Source.WE_HIRING | Source.TECNO_EMPLEO:
                return_value = cls(**data, source=source)
            case _:
                # TODO: hacer algo mejor aquí
                message = "Not a valid source. WTF, list of sources {}".format(
                    str(Source.__dict__.get("_member_names_")))
                raise TypeError(message)

        return_value.petition_id = petition

        return return_value
        # ***************************************  Output methods *************************************** #

    def to_mongo(self) -> dict:
        """
        Get a mongo friendly version of __dict__ of the object.
        :return: dictionary of the object
        """
        # return_dict = copy.copy(self.__dict__)
        # for key, value in return_dict.items():
        return_dict: dict = {}
        for key, value in self.__dict__.items():
            if value:
                if key == 'mongo_id':  # Rename mongo_id so that is the actual id of when in mongo
                    return_dict["_id"]: str = value
                elif isinstance(value, datetime.date):  # Serialize dates
                    return_dict[key]: str = str(value)
                # elif isinstance(value, str):  # Get rid of unwanted characters
                #     return_dict[key]: str = re.sub(r'\"', r'"', self.__dict__.get(key))
                elif isinstance(value, enum.Enum):  # for enums
                    return_dict[key]: str = value.value
                    # return_dict[key]: dict[str: str] = Job._api_format(value.value, value_type.__name__)
                else:
                    return_dict[key]: any = value

        return return_dict

    def to_api(self) -> dict:
        return_dict: dict = {}
        for key, value in self.__dict__.items():
            if value:
                value_type = type(value)
                if key == 'mongo_id':  # Rename mongo_id so that is the actual id of when in mongo
                    return_dict["_id"]: dict[str: str] = Offer._api_format(str(value), value_type.__name__)
                elif value_type == datetime.date:  # Serialice dates
                    return_dict[key]: dict[str: str] = Offer._api_format(str(value),
                                                                         value_type.__name__)
                # elif value_type == Source:
                elif isinstance(value, enum.Enum):  # for enums
                    return_dict[key]: dict[str: str] = Offer._api_format(value.value, value_type.__name__)
                else:
                    return_dict[key]: dict[str: any | str] = Offer._api_format(value, value_type.__name__)
        return return_dict

    def save(self, collection: pymongo.collection.Collection | None = None) -> pymongo.collection.UpdateResult:
        """Saves the object in the mongo collection passed with the format specified in to_mongo().

        :param collection: collection where the objects is to be saved
        :return: The update result of mongo
        """
        if collection is None:
            # TODO: esto se debería meter en un fichero
            collection = mongo_conn.connect_to_offers()

        mongo_filter = {'title': self.title, 'company': self.company, 'petition_id': self.petition_id}

        if self.id is not None:
            mongo_filter['id'] = str(self.post_date)

        mongo_dict = self.to_mongo()
        import classes.offer_consts as offer
        mongo_dict[offer.UPDATE_DATE] = date.today()
        return collection.update_one(mongo_filter, {'$set': mongo_dict}, upsert=True)

    # ******************************************* Validator methods ******************************************* #
    def validate_types(self) -> (bool, [str]):
        """
        Validates that all the types are correct.
        :return: If mistakes and mistakes made.
        """
        schema: dict = Offer.__dict__.get(Offer.SCHEMA)
        # validator: bool = True
        mistakes: [str] = []
        for key, value in self.__dict__.items():
            # print(type(annotations.get(key)), key) # Para info por si se necesita
            if not isinstance(value, schema.get(key) | None):
                mistakes.append(
                    Offer.SCHEMA_WRONG_TYPE_MESSAGE.format(key, schema.get(key).__name__, type(value).__name__))

        return mistakes == [], mistakes

    @staticmethod
    def validate_input(input_data: dict) -> (bool, [str]):

        schema: dict = Offer.__dict__.get(Offer.SCHEMA)
        mistakes: [str] = []
        for key, value in input_data.items():
            # print(type(annotations.get(key)), key) # Para info por si se necesita
            if not isinstance(value, schema.get(key) | None):
                mistakes.append(
                    Offer.SCHEMA_WRONG_TYPE_MESSAGE.format(key, schema.get(key).__name__, type(value).__name__))
            elif key not in schema.keys():
                mistakes.append(Offer.SCHEMA_WRONG_KEY_MESSAGE.format(key, schema.keys()))

        return mistakes == [], mistakes


class Petition(BaseModel):
    mongo_id: ObjectId | None = None
    user: str = "anon"
    creation_datetime: datetime.datetime
    query: str
    location: str | None = None
    disabled: bool = False

    @classmethod
    def from_mongo(cls, input_dict: dict):
        mongo_dict = copy.deepcopy(input_dict)

        if "_id" in mongo_dict.keys():
            mongo_dict["mongo_id"] = mongo_dict.pop("_id")

        return cls(**mongo_dict)

    def to_mongo(self):
        dictionary = {}
        for key, value in dict(self).items():
            if value is not None:
                dictionary[key] = value

        if "mongo_id" in dictionary.keys():
            dictionary["_id"] = dictionary.pop("mongo_id")

        return dictionary

    def to_api(self):
        return to_api(self)

    def save(self):
        mfilter = {"user": self.user}
        if self.mongo_id is not None:
            mfilter["_id"] = self.mongo_id
        else:
            mfilter["query"] = self.query

        return mongo_conn.connect_to_petitions().update_one(mfilter, {'$set': self.to_mongo()}, upsert=True)


# For USER
class Permission(enum.Enum):
    ADMIN = "admin"
    READ_EVERYTHING = "read"


class User(BaseModel):
    mongo_id: ObjectId | None = None
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None
    permits: list[Permission]


class UserInDB(User):
    hashed_password: str

    def to_mongo(self):
        return {key: value for key, value in dict(self).items() if value is not None}

    def save(self):
        mongo_filter = {
            "username": self.username
        }

        if self.mongo_id is not None:
            mongo_filter["_id"] = self.mongo_id

        return connect_to_users().update_one(mongo_filter, {"$set": self.to_mongo()}, upsert=True)
