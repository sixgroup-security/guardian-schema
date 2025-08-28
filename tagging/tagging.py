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

import uuid
import enum
from datetime import datetime
from typing import List, Set
from pydantic import BaseModel, ConfigDict
from sqlmodel import Field, SQLModel, Relationship, Column, ForeignKey
from sqlalchemy import Enum, UniqueConstraint
from sqlalchemy.sql import func
from sqlalchemy.dialects import postgresql

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class TagCategoryEnum(enum.IntEnum):
    project = enum.auto()
    procedure = enum.auto()
    application = enum.auto()
    vulnerability_template = enum.auto()
    measure = enum.auto()
    # Project-specific enums
    test_reason = enum.auto()
    environment = enum.auto()
    # Application-specific enums
    classification = enum.auto()  # Tags managed by external inventory management application (e.g. Internal).
    inventory = enum.auto()  # Tags managed by external inventory management application (e.g. Internet-facing).
    deployment_model = enum.auto()
    # Common enums (applies to projects, applications, vulnerabilities and measures)
    general = enum.auto()
    # Tags for procedures
    vrt_category = enum.auto()  # Not used anymore
    owasp_top_ten = enum.auto()  # Not used anymore


class TagProjectTestReason(SQLModel, table=True):
    """
    Mapping table between projects and tags to store why the test is performed (e.g. PCI-DSS).
    """
    tag_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("tag.id", ondelete="CASCADE"), primary_key=True)
    )
    project_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("project.id", ondelete="CASCADE"), primary_key=True)
    )
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))


class TagProjectEnvironment(SQLModel, table=True):
    """
    Mapping table documenting the environment on which the project is performed (e.g., production).
    """
    tag_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("tag.id", ondelete="CASCADE"), primary_key=True)
    )
    project_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("project.id", ondelete="CASCADE"), primary_key=True)
    )
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))


class TagProjectClassification(SQLModel, table=True):
    """
    Mapping table documenting the classification level of the in-scope applications.
    """
    tag_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("tag.id", ondelete="CASCADE"), primary_key=True)
    )
    project_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("project.id", ondelete="CASCADE"), primary_key=True)
    )
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))


class TagProjectGeneral(SQLModel, table=True):
    """
    Mapping table documenting general tags.
    """
    tag_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("tag.id", ondelete="CASCADE"), primary_key=True)
    )
    project_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("project.id", ondelete="CASCADE"), primary_key=True)
    )
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))


class TagApplicationInventory(SQLModel, table=True):
    """
    Mapping table for tags managed by external inventory management application (e.g. Internet-facing).
    """
    tag_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("tag.id", ondelete="CASCADE"), primary_key=True)
    )
    application_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("application.id", ondelete="CASCADE"), primary_key=True)
    )
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))


class TagApplicationClassification(SQLModel, table=True):
    """
    Mapping table for tags managed by external inventory management application for classification (e.g., confidential).
    """
    tag_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("tag.id", ondelete="CASCADE"), primary_key=True)
    )
    application_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("application.id", ondelete="CASCADE"), primary_key=True)
    )
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))


class TagApplicationGeneral(SQLModel, table=True):
    """
    Mapping table for tags managed by user.
    """
    tag_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("tag.id", ondelete="CASCADE"), primary_key=True)
    )
    application_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("application.id", ondelete="CASCADE"), primary_key=True)
    )
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))


class TagApplicationDeploymentModel(SQLModel, table=True):
    """
    Mapping table for tags managed by external inventory management application for defining how/where the application
    is deployed (e.g., on-prem).
    """
    tag_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("tag.id", ondelete="CASCADE"), primary_key=True)
    )
    application_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("application.id", ondelete="CASCADE"), primary_key=True)
    )
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))


class TagMeasureGeneral(SQLModel, table=True):
    """
    Mapping table for measure tags managed by user.
    """
    tag_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("tag.id", ondelete="CASCADE"), primary_key=True)
    )
    measure_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("measure.id", ondelete="CASCADE"), primary_key=True)
    )
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))


class TagTestProcedureGeneral(SQLModel, table=True):
    """
    Mapping table for measure tags managed by user.
    """
    tag_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("tag.id", ondelete="CASCADE"), primary_key=True)
    )
    test_procedure_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("testprocedure.id", ondelete="CASCADE"), primary_key=True)
    )
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))


class TagVulnerabilityTemplateGeneral(SQLModel, table=True):
    """
    Mapping table for measure tags managed by user.
    """
    tag_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("tag.id", ondelete="CASCADE"), primary_key=True)
    )
    vulnerability_template_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("vulnerabilitytemplate.id", ondelete="CASCADE"), primary_key=True)
    )
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))


class Tag(SQLModel, table=True):
    """
    Store information about a tag in the database.
    """
    id: uuid.UUID | None = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    name: str = Field(index=True)
    categories: Set[TagCategoryEnum] = Field(
        default={},
        sa_column=Column(postgresql.ARRAY(Enum(TagCategoryEnum)), nullable=False)
    )
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Relationship definitions
    projects_reasons: List["Project"] = Relationship(
        back_populates="reasons",
        link_model=TagProjectTestReason
    )
    projects_environment: List["Project"] = Relationship(
        back_populates="environments",
        link_model=TagProjectEnvironment
    )
    projects_classification: List["Project"] = Relationship(
        back_populates="classifications",
        link_model=TagProjectClassification
    )
    projects_general: List["Project"] = Relationship(
        back_populates="tags",
        link_model=TagProjectGeneral
    )
    # Relationships in regard to applications
    applications_inventory: List["Application"] = Relationship(
        back_populates="inventory_tags",
        link_model=TagApplicationInventory
    )
    applications_classification: List["Application"] = Relationship(
        back_populates="classification_tags",
        link_model=TagApplicationClassification
    )
    applications_general: List["Application"] = Relationship(
        back_populates="general_tags",
        link_model=TagApplicationGeneral
    )
    applications_deployment_model: List["Application"] = Relationship(
        back_populates="deployment_model_tags",
        link_model=TagApplicationDeploymentModel
    )
    # Relationships in regard to measures
    measures_general: List["Measure"] = Relationship(
        back_populates="general_tags",
        link_model=TagMeasureGeneral
    )
    # Relationships in regard to playbooks
    test_procedure_general: List["TestProcedure"] = Relationship(
        back_populates="general_tags",
        link_model=TagTestProcedureGeneral
    )
    # Relationships in regard to vulnerability templates
    vulnerability_templates_general: List["VulnerabilityTemplate"] = Relationship(
        back_populates="general_tags",
        link_model=TagVulnerabilityTemplateGeneral
    )

    __table_args__ = (
        UniqueConstraint('name', 'categories'),
    )


class TagCreate(BaseModel):
    """
    This is the tag schema for creating a tag via FastAPI.
    """
    name: str


class TagLookup(TagCreate):
    """
    This is the tag schema for looking up a tag via FastAPI.
    """
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str

    def __eq__(self, other):
        return self.id == other.id


class TagReport(TagLookup):
    """
    Schema for creating the final JSON object based on which the report is created.
    """
    model_config = ConfigDict(from_attributes=True)
