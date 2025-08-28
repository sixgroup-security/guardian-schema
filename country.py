# This file is part of Guardian.
#
# Guardian is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Guardian is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with MyAwesomeProject. If not, see <https://www.gnu.org/licenses/>.

import uuid
from typing import List
from sqlalchemy.sql import func
from datetime import datetime
from sqlmodel import Field, SQLModel, Relationship
from pydantic import BaseModel, Field as PydanticField, field_serializer, AliasChoices

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class Country(SQLModel, table=True):
    """
    Store and manage location information.
    """
    id: uuid.UUID = Field(primary_key=True,
                          index=True,
                          sa_column_kwargs=dict(server_default=func.gen_random_uuid()))
    name: str = Field(unique=True)
    code: str = Field(unique=True)
    phone: str = Field()
    # Countries are sorted per default desc and name asc. Hence, it allows prioritizing countries in dropdown menus.
    default: bool = Field(sa_column_kwargs=dict(server_default='false'))
    svg_image: str = Field()
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Relationship definitions
    report_languages: List["ReportLanguage"] = Relationship(back_populates="country")
    entities: List["Entity"] = Relationship(back_populates="location")
    projects: List["Project"] = Relationship(back_populates="location")


class CountryRead(SQLModel):
    """
    This is the country schema. It is used by the FastAPI to return information about a country.
    """
    id: uuid.UUID
    name: str
    code: str
    phone: str
    default: bool


class CountryLookup(BaseModel):
    id: uuid.UUID
    name: str
    code: str = PydanticField(
        serialization_alias="country_code",
        validation_alias=AliasChoices("code", "country_code")
    )

    @field_serializer('id', when_used='json')
    def serialize_id(self, attribute: uuid.UUID) -> str:
        return str(attribute)


class CountryReport(SQLModel):
    """
    Schema for creating the final JSON object based on which the report is created.
    """
    id: uuid.UUID
    name: str = Field(unique=True)
    code: str = Field(unique=True)
    svg_image: str = PydanticField()
