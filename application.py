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
from uuid import UUID
from datetime import datetime, date
from typing import List, Set, Any

from sqlmodel import Field, SQLModel, Relationship, Column, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import backref
from schema.util import EntityLookup
from schema.tagging.tagging import (
    Tag, TagApplicationInventory, TagApplicationClassification, TagApplicationGeneral, TagApplicationDeploymentModel,
    TagLookup
)
from pydantic import (
    ConfigDict, Field as PydanticField, AliasChoices, BaseModel, computed_field
)

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


# Make sure to also update the corresponding CASE statement of the SQL statement in routers\applications.py
class ApplicationState(enum.IntEnum):
    planned = 0
    development = 10
    production = 20
    decommissioned = 30


# Make sure to also update the corresponding CASE statement of the SQL statement in routers\applications.py
class PeriodicityParameterEnum(enum.Enum):
    manual = 10
    out_of_scope = 20
    decommissioned = 100


class OverdueStatusEnum(enum.Enum):
    no_overdue = 10
    ongoing_project = 20
    no_project = 30


class ApplicationProject(SQLModel, table=True):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    project_id: UUID = Field(
        sa_column=Column(ForeignKey("project.id", ondelete="CASCADE"), primary_key=True)
    )
    application_id: UUID = Field(
        sa_column=Column(ForeignKey("application.id", ondelete="CASCADE"), primary_key=True)
    )
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # All relationship definitions
    project: "Project" = Relationship(
        sa_relationship_kwargs=dict(
            backref=backref(
                "application_project_links",
                cascade="delete, delete-orphan",
                overlaps="projects,applications"
            ),
            overlaps="projects,applications"
        )
    )
    application: "Application" = Relationship(
        sa_relationship_kwargs=dict(
            backref=backref(
                "application_project_links",
                cascade="delete, delete-orphan",
                overlaps="projects,applications"
            ),
            overlaps="projects,applications"
        )
    )


class Application(SQLModel, table=True):
    """
    Store information about a project in the database.
    """
    id: UUID | None = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    application_id: str = Field(index=True, unique=True)
    name: str = Field(index=True)
    state: ApplicationState | None = Field()
    description: str | None = Field()
    # Autocomputed by stored procedure to determine when the last pentest was executed on the application
    last_pentest: date | None = Field()
    pentest_this_year: int = Field(sa_column_kwargs=dict(server_default='0'))
    next_pentest: date | None = Field()
    pentest_periodicity: int | None = Field()
    overdue_status: OverdueStatusEnum = Field()
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    periodicity_parameter: PeriodicityParameterEnum | None = Field()
    in_scope: bool = Field(default=True)
    manual_pentest_periodicity: int | None = Field()
    periodicity_details: str = Field(nullable=True)
    # Foreign keys
    owner_id: UUID | None = Field(foreign_key="entity.id")
    manager_id: UUID | None = Field(foreign_key="entity.id")
    # All relationship definitions
    projects: List["Project"] = Relationship(
        back_populates="applications",
        link_model=ApplicationProject
    )
    owner: "Entity" = Relationship(
        sa_relationship_kwargs=dict(foreign_keys="[Application.owner_id]"),
        back_populates="owns_applications"
    )
    manager: "Entity" = Relationship(
        sa_relationship_kwargs=dict(foreign_keys="[Application.manager_id]"),
        back_populates="manages_applications"
    )
    inventory_tags: List[Tag] = Relationship(
        back_populates="applications_inventory",
        link_model=TagApplicationInventory
    )
    classification_tags: List[Tag] = Relationship(
        back_populates="applications_classification",
        link_model=TagApplicationClassification
    )
    general_tags: List[Tag] = Relationship(
        back_populates="applications_general",
        link_model=TagApplicationGeneral
    )
    deployment_model_tags: List[Tag] = Relationship(
        back_populates="applications_deployment_model",
        link_model=TagApplicationDeploymentModel
    )


class ApplicationLookup(SQLModel):
    id: UUID
    application_id: str = PydanticField(serialization_alias="app_id")
    name: str = PydanticField(exclude=True)

    @computed_field
    def label(self) -> str:
        return f"{self.application_id} - {self.name}"


class ApplicationCreateUpdateBase(BaseModel):
    """
    It represents the base class for updating or creating an application.
    """
    application_id: str
    name: str
    state: ApplicationState
    description: str | None = PydanticField(default=None)
    in_scope: bool = PydanticField(
        default=True,
        validation_alias=AliasChoices("in_scope", "in_scoped")
    )
    manual_pentest_periodicity: int | None = PydanticField(default=None)
    periodicity_details: str | None = PydanticField(default=None)
    last_pentest: date | None = PydanticField(default=None)
    next_pentest: date | None = PydanticField(default=None)
    pentest_periodicity: int | None = PydanticField(default=None)
    periodicity_parameter: PeriodicityParameterEnum | None = PydanticField(default=None)

    def __eq__(self, other: Any) -> bool:
        return (
            self.application_id == other.application_id and
            self.name == other.name and
            self.state == other.state and
            self.description == other.description and
            self.pentest_periodicity == other.pentest_periodicity and
            self.inventory_tags == other.inventory_tags and
            self.classification_tags == other.classification_tags and
            self.general_tags == other.general_tags and
            self.deployment_model_tags == other.deployment_model_tags and
            self.in_scope == other.in_scope and
            self.manual_pentest_periodicity == other.manual_pentest_periodicity and
            self.periodicity_details == other.periodicity_details and
            self.last_pentest == other.last_pentest and
            self.next_pentest == other.next_pentest and
            self.pentest_periodicity == other.pentest_periodicity and
            self.periodicity_parameter == other.periodicity_parameter
        )


class ApplicationCreate(ApplicationCreateUpdateBase):
    """
    This is the application schema for creating an application via FastAPI.
    """
    owner_id: UUID | None = PydanticField(validation_alias=AliasChoices("owner", "owner_id"))
    manager_id: UUID | None = PydanticField(validation_alias=AliasChoices("manager", "manager_id"))
    inventory_tags: Set[UUID] | None = PydanticField(default=[])
    classification_tags: Set[UUID] | None = PydanticField(default=[])
    general_tags: Set[UUID] | None = PydanticField(default=[])
    deployment_model_tags: Set[UUID] | None = PydanticField(default=[])

    def __eq__(self, other: Any) -> bool:
        return (
            super().__eq__(other) and
            self.owner_id == other.owner_id and
            self.manager_id == other.manager_id and
            self.inventory_tags == other.inventory_tags and
            self.classification_tags == other.classification_tags and
            self.general_tags == other.general_tags and
            self.deployment_model_tags == other.deployment_model_tags
        )


class ApplicationRead(ApplicationCreateUpdateBase):
    """
    This is the application schema for reading an application via FastAPI.
    """
    id: UUID
    owner: EntityLookup | None = PydanticField(default=None)
    manager: EntityLookup | None = PydanticField(default=None)
    inventory_tags: List[TagLookup] | None = PydanticField(default=[])
    classification_tags: List[TagLookup] | None = PydanticField(default=[])
    general_tags: List[TagLookup] | None = PydanticField(default=[])
    deployment_model_tags: List[TagLookup] | None = PydanticField(default=[])

    def __eq__(self, other: Any) -> bool:
        return (
            super().__eq__(other) and
            # self.owner == other.owner and
            # self.manager == other.manager and
            self.inventory_tags == other.inventory_tags and
            self.classification_tags == other.classification_tags and
            self.general_tags == other.general_tags and
            self.deployment_model_tags == other.deployment_model_tags and
            self.last_pentest == other.last_pentest and
            self.next_pentest == other.next_pentest and
            self.pentest_periodicity == other.pentest_periodicity and
            self.periodicity_parameter == other.periodicity_parameter
        )


class ApplicationUpdate(ApplicationCreate):
    """
    This is the application schema for updating an application via FastAPI.
    """
    id: UUID


class ApplicationProjectCreate(BaseModel):
    """
    This is the schema for creating a batch of projects
    """
    applications: List[UUID]
    type: int
    start: datetime
    location_id: UUID = PydanticField(alias="location")


class ApplicationReport(BaseModel):
    """
    Schema for creating the final JSON object based on which the report is created.
    """
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    application_id: str
    name: str
    state: ApplicationState
    description: str | None = PydanticField(default=None)
    owner: EntityLookup | None = PydanticField(default=None)
    manager: EntityLookup | None = PydanticField(default=None)
    inventory_tags: List[TagLookup] | None = PydanticField(default=[])
    classification_tags: List[TagLookup] | None = PydanticField(default=[])
    general_tags: List[TagLookup] | None = PydanticField(default=[])
    deployment_model_tags: List[TagLookup] | None = PydanticField(default=[])
    in_scope: bool = PydanticField(default=True)
    manual_pentest_periodicity: int | None = PydanticField(default=None)
    periodicity_details: str | None = PydanticField(default=None)
