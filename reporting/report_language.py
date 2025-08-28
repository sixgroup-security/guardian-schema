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
from datetime import datetime
from typing import List, Any
from sqlmodel import Field, SQLModel, Relationship
from schema.country import CountryLookup, Country, CountryReport
from sqlalchemy.sql import func
from pydantic import ConfigDict, Field as PydanticField, AliasChoices, computed_field

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class ReportLanguage(SQLModel, table=True):
    """
    Store and manage language information.
    """
    id: uuid.UUID = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    name: str = Field(unique=True)
    language_code: str = Field(unique=True)
    is_default: bool = Field(default=False, sa_column_kwargs=dict(server_default='false'))
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Foreign keys
    country_id: uuid.UUID = Field(unique=True, foreign_key="country.id")
    # Relationship definitions
    measure_details: List["MeasureLanguage"] = Relationship(back_populates="language")
    report_template_details: List["ReportTemplateLanguage"] = Relationship(back_populates="language")
    rating_comments: List["RatingLanguage"] = Relationship(back_populates="language")
    playbook_details: List["PlaybookLanguage"] = Relationship(back_populates="language")
    test_procedure_details: List["TestProcedureLanguage"] = Relationship(back_populates="language")
    vulnerability_template_details: List["VulnerabilityTemplateLanguage"] = Relationship(back_populates="language")
    country: Country = Relationship(
        sa_relationship_kwargs=dict(foreign_keys="[ReportLanguage.country_id]"),
        back_populates="report_languages"
    )
    reports: List["Report"] = Relationship(back_populates="report_language")
    users: List["User"] = Relationship(back_populates="report_language")


class ReportLanguageCreateUpdateBase(SQLModel):
    """
    This is the report language schema. It represents the base class for updating or creating a report languages.
    """
    model_config = ConfigDict(from_attributes=True, extra="ignore")

    name: str
    language_code: str
    is_default: bool | None = Field(default=False)

    def __eq__(self, other: Any) -> bool:
        return (
            self.name == other.name and
            self.language_code == other.language_code and
            self.is_default == other.is_default
        )


class ReportLanguageCreate(ReportLanguageCreateUpdateBase):
    """
    This is the application schema for creating, reading and updating a report language via FastAPI.
    """
    country_id: uuid.UUID = PydanticField(
        serialization_alias="country",
        validation_alias=AliasChoices('country', 'country_id'))


class ReportLanguageRead(ReportLanguageCreateUpdateBase):
    """
    This is the report template schema. It is used by the FastAPI to read a report language.
    """

    id: uuid.UUID
    country_id: CountryLookup = PydanticField(alias="country")


class ReportLanguageUpdate(ReportLanguageCreateUpdateBase):
    id: uuid.UUID
    country_id: uuid.UUID = PydanticField(validation_alias=AliasChoices('country', 'country_id'))


class ReportLanguageLookup(SQLModel):
    id: uuid.UUID
    name: str
    is_default: bool
    language_code: str
    country: Country = PydanticField(exclude=True)

    @computed_field
    def country_code(self) -> str:
        return self.country.code


class ReportLanguageReport(SQLModel):
    """
    Schema for creating the final JSON object based on which the report is created.
    """
    id: uuid.UUID
    name: str
    language_code: str
    country: CountryReport | None = PydanticField(default=None)

    @property
    def country_code(self) -> str:
        return self.country.code

    @property
    def flag(self) -> str:
        return self.country.svg_image
