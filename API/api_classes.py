"""
Classes used by the API as input.
"""
import datetime
from pydantic import BaseModel

import classes
from classes.dao import User


class PetitionRequest(BaseModel):
    query: str
    location: str | None = None


class OfferQuery(BaseModel):
    id: str | None = None
    petition_id: str | None = None
    title: str | None = None
    company: str | None = None
    province: str | None = None
    city: str | None = None
    category: str | None = None
    subcategory: str | None = None
    post_date: datetime.date | None = None
    update_date: datetime.date | None = None
    add_date: datetime.date | None = None
    contract_type: str | None = None
    workday: str | None = None
    salary_min: int | None = None
    salary_max: int | None = None
    salary_period: str | None = None
    experience_min: str | None = None
    requirement_min: str | None = None
    link_job: str | None = None
    link_company: str | None = None
    link_logo: str | None = None


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class UserRequest(User):
    password: str
