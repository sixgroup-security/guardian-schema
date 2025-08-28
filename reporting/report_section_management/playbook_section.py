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
from typing import List, Dict, Optional, Any
from sqlmodel import Field, Relationship
from sqlalchemy import ForeignKey, CheckConstraint, Column, INTEGER
from sqlalchemy.sql import func
from pydantic import BaseModel, Field as PydanticField, ConfigDict, computed_field
from schema.reporting.report_section_management import SectionStatistics
from schema.reporting.report_section_management.report_procedure import (
    ReportProcedure, ReportProcedureTreeNode, ReportProcedureReport
)

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class PlaybookSection(SectionStatistics, table=True):
    """
    Store information about a playbook sections in the database.
    """
    __tablename__ = "testguidesection"
    id: uuid.UUID = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    name: str = Field()
    order: int = Field(sa_column=Column(INTEGER, unique=False, nullable=False))
    description: str | None = Field()
    # Foreign keys
    parent_id: uuid.UUID | None = Field(sa_column=Column(ForeignKey("testguidesection.id", ondelete="CASCADE")))
    section_id: uuid.UUID | None = Field(foreign_key=("reportsectiontestguide.id"))
    # Relationship definitions
    playbook: "ReportSectionPlaybook" = Relationship(back_populates="playbook_sections")
    children: List["PlaybookSection"] = Relationship(
        sa_relationship_kwargs=dict(
            # primaryjoin="PlaybookSection.id==PlaybookSection.parent_id",
            order_by="asc(PlaybookSection.order)",
            cascade="all,delete,delete-orphan"
        ),
        back_populates="parent"
    )
    parent: Optional["PlaybookSection"] = Relationship(
        sa_relationship_kwargs=dict(
            remote_side="[PlaybookSection.id]",
            # primaryjoin="PlaybookSection.id==PlaybookSection.parent_id",
            back_populates="children"
        )
    )
    procedures: List[ReportProcedure] = Relationship(
        sa_relationship_kwargs=dict(
            cascade="all,delete,delete-orphan",
            order_by="asc(ReportProcedure.order)",
            back_populates="section"
        )
    )

    __table_args__ = (
        CheckConstraint(
            "(parent_id IS NULL AND section_id IS NOT NULL) OR (parent_id IS NOT NULL AND section_id IS NULL)",
            name="parent_section_check"
        ),
    )

    def get_section(self, section_id: uuid.UUID) -> Optional["PlaybookSection"]:
        """
        Recursively gets the section associated with this playbook section.
        """
        if self.id == section_id:
            return self
        for child in self.children:
            result = child.get_section(section_id)
            if result:
                return result
        return None

    def get_procedure(self, procedure_id: uuid.UUID) -> ReportProcedure | None:
        """
        Gets the procedure associated with this playbook section.
        """
        for procedure in self.procedures:
            if procedure.id == procedure_id:
                return procedure
        return None

    def get_item(self, procedure_id: uuid.UUID = None, vulnerability_id: uuid.UUID = None):
        try:
            procedure = self.get_procedure(procedure_id)
            if vulnerability_id:
                return procedure.get_item(vulnerability_id)
            return procedure
        except ValueError:
            ...
        return None


class PlaybookSectionTreeNode(BaseModel):
    schema_version: str = "1.0"
    id: uuid.UUID
    type: str = "container"
    name: str = PydanticField(exclude=True)
    description: str = PydanticField(exclude=True)
    children_: List[Any] = PydanticField(default=[], exclude=True, validation_alias="children")
    procedures: List[ReportProcedure] = PydanticField(default=[], exclude=True)

    @computed_field
    def info(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "description": self.description
        }

    @computed_field
    def children(self) -> List[Any]:
        result = [
            PlaybookSectionTreeNode(
                **item.model_dump(),
                children=item.children,
                procedures=item.procedures
            ) for item in self.children_
        ]
        result += [
            ReportProcedureTreeNode(
                **item.model_dump(),
                vulnerabilities=item.vulnerabilities,
                source_procedure=item.source_procedure
            ) for item in self.procedures
        ]
        return result


class PlaybookSectionReport(BaseModel):
    """
    Schema for creating the final JSON object based on which the report is created.
    """
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    description: str
    children: List["PlaybookSectionReport"] = PydanticField(default=[])
    procedures: List[ReportProcedureReport] = PydanticField(default=[])
