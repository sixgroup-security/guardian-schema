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
# along with Guardian. If not, see <https://www.gnu.org/licenses/>.

import enum
import uuid
from datetime import datetime
from typing import List, Any
from sqlmodel import Field, SQLModel, Relationship, Column, ForeignKey
from sqlalchemy import UniqueConstraint
from sqlalchemy.sql import func
from schema.util import UserLookup, serialize_uuids, validate_uuids
from schema.country import Country, CountryLookup
from schema.application import Application
from pydantic import BaseModel, ConfigDict, Field as PydanticField, AliasChoices, field_serializer, field_validator

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class EntityRoleEnum(enum.IntEnum):
    customer = 0
    provider = 10


class Entity(SQLModel, table=True):
    """
    Store information about an entity in the database.
    """
    id: uuid.UUID | None = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    name: str = Field(index=True)
    abbreviation: str | None = Field(unique=True)
    address: str | None = Field()
    role: EntityRoleEnum = Field()
    # Foreign keys
    location_id: uuid.UUID = Field(foreign_key="country.id")
    manager_id: uuid.UUID | None = Field(
        sa_column=Column(ForeignKey("user.id", name="entity_manager_id_fkey"))
    )
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # All relationship definitions
    # https://github.com/tiangolo/sqlmodel/issues/10
    location: Country = Relationship(back_populates="entities")
    provider_projects: List["Project"] = Relationship(
        sa_relationship_kwargs=dict(foreign_keys="[Project.provider_id]"),
        back_populates="provider"
    )
    customer_projects: List["Project"] = Relationship(
        sa_relationship_kwargs=dict(foreign_keys="[Project.customer_id]"),
        back_populates="customer"
    )
    # Testers working for the provider
    provider_users: List["User"] = Relationship(
        sa_relationship_kwargs=dict(foreign_keys="[User.provider_id]"),
        back_populates="provider"
    )
    # Users that we can grant access to a customer's project
    customer_users: List["User"] = Relationship(
        sa_relationship_kwargs=dict(foreign_keys="[User.customer_id]"),
        back_populates="customer"
    )
    manager: "User" = Relationship(
        sa_relationship_kwargs=dict(foreign_keys="[Entity.manager_id]"),
        back_populates="responsible_for"
    )
    owns_applications: List[Application] = Relationship(
        sa_relationship_kwargs=dict(foreign_keys="[Application.owner_id]"),
        back_populates="owner"
    )
    manages_applications: List[Application] = Relationship(
        sa_relationship_kwargs=dict(foreign_keys="[Application.manager_id]"),
        back_populates="manager"
    )
    __table_args__ = (
        UniqueConstraint('name', 'location_id', 'role'),
    )


class EntityReport(SQLModel):
    """
    Schema for creating the final JSON object based on which the report is created.
    """
    id: uuid.UUID
    name: str
    abbreviation: str | None = Field()
    address: str | None = Field()


class LocationIdMixin(BaseModel):
    """
    This mixin is used to add location information to a model.

    This class can be used to add a provider with all its serialization and validation logic to a model.
    """
    location_id: uuid.UUID = PydanticField(
        serialization_alias="location",
        validation_alias=AliasChoices("location", "location_id")
    )

    @field_serializer('location_id')
    def serialize_location_id(self, location_id: uuid.UUID) -> str:
        return serialize_uuids(location_id)

    @field_validator('location_id')
    def validate_location_id(cls, location_id: uuid.UUID | str) -> uuid.UUID:
        return validate_uuids(location_id)


class ManagerIdMixin(BaseModel):
    """
    This mixin is used to add manager information to a model.

    This class can be used to add a provider with all its serialization and validation logic to a model.
    """
    manager_id: uuid.UUID = PydanticField(
        serialization_alias="manager",
        validation_alias=AliasChoices("manager", "manager_id")
    )

    @field_serializer('manager_id')
    def serialize_manager_id(self, manager_id: uuid.UUID) -> str:
        return serialize_uuids(manager_id)

    @field_validator('manager_id')
    def validate_manager_id(cls, manager_id: uuid.UUID | str) -> uuid.UUID:
        return validate_uuids(manager_id)


class ProviderIdMixin(BaseModel):
    """
    This mixin is used to add provider information to a model.

    This class can be used to add a provider with all its serialization and validation logic to a model.
    """
    provider_id: uuid.UUID = PydanticField(
        serialization_alias="provider",
        validation_alias=AliasChoices("provider", "provider_id")
    )

    @field_serializer('provider_id')
    def serialize_provider_id(self, provider_id: uuid.UUID) -> str:
        return serialize_uuids(provider_id)

    @field_validator('provider_id')
    def validate_provider_id(cls, provider_id: uuid.UUID | str) -> uuid.UUID:
        return validate_uuids(provider_id)


class EntityCreateUpdateBase(SQLModel):
    """
    It represents the base class for updating or creating an entity.
    """
    model_config = ConfigDict(extra="ignore")

    name: str
    abbreviation: str | None = PydanticField(None)
    address: str | None = PydanticField(None)

    def __eq__(self, other: Any) -> bool:
        return self.name == other.name and self.abbreviation == other.abbreviation and self.address == other.address


class ProviderCreate(EntityCreateUpdateBase, LocationIdMixin):
    """
    This is the entity schema for creating a provider via FastAPI.
    """
    ...


class CustomerCreate(EntityCreateUpdateBase, LocationIdMixin, ManagerIdMixin):
    """
    This is the entity schema for creating a customer via FastAPI.
    """
    ...


class ProviderRead(EntityCreateUpdateBase):
    """
    This is the entity schema for reading a provider via FastAPI.
    """
    id: uuid.UUID
    location: CountryLookup = PydanticField()


class CustomerRead(EntityCreateUpdateBase):
    """
    This is the entity schema for reading a customer via FastAPI.
    """
    id: uuid.UUID
    location: CountryLookup = PydanticField()
    manager: UserLookup | None = PydanticField(None)

    def __eq__(self, other: CustomerCreate) -> bool:
        result = super().__eq__(other)
        return result and self.manager.id == other.manager_id and self.location.id == other.location_id


class ProviderUpdate(ProviderCreate):
    """
    This is the entity schema for updating a provider via FastAPI.
    """
    id: uuid.UUID


class CustomerUpdate(CustomerCreate):
    """
    This is the entity schema for updating a customer via FastAPI.
    """
    id: uuid.UUID
