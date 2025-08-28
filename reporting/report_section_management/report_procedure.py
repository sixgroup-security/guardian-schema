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
import enum
from typing import List
from sqlmodel import SQLModel, Field, Relationship
from sqlalchemy import Column, INTEGER, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import backref
from pydantic import BaseModel, Field as PydanticField, ConfigDict, computed_field
from schema.reporting.file import File
from schema.reporting.vulnerability import TestPriority
from schema.reporting.report_section_management import SectionStatistics
from schema.reporting.report_section_management.vulnerability import (
    Vulnerability, VulnerabilityTreeNode, VulnerabilityReport
)
from schema.reporting.vulnerability.test_procedure import TestProcedure
from datetime import datetime

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class ReviewStatus(enum.IntEnum):
    pending = 0
    # Not applicable
    na = 10
    # Work in progress
    wip = 20
    not_tested = 30
    review = 40
    completed = 50


class ReportProcedureFile(SQLModel, table=True):
    procedure_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("reportprocedure.id", ondelete="CASCADE"), primary_key=True))
    file_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("file.id", ondelete="CASCADE"), primary_key=True))
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Relationship definitions
    procedure: List["ReportProcedure"] = Relationship(
        sa_relationship_kwargs=dict(
            backref=backref(
                "file_mappings",
                cascade="delete, delete-orphan",
                overlaps="report_procedures,files"
            ),
            overlaps="report_procedures,files"
        )
    )
    file: List["File"] = Relationship(
        sa_relationship_kwargs=dict(
            backref=backref(
                "procedure_mappings",
                cascade="delete, delete-orphan",
                overlaps="report_procedures,files"
            ),
            overlaps="report_procedures,files"
        )
    )


class ReportProcedure(SectionStatistics, table=True):
    """
    Store information about a report procedure in the database.
    """
    id: uuid.UUID = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    name: str = Field()
    objective: str | None = Field()
    order: int = Field(sa_column=Column(INTEGER, unique=False, nullable=False))
    status: ReviewStatus = Field(sa_column_kwargs=dict(server_default=ReviewStatus.pending.name))
    internal_documentation: str | None = Field()
    # Defines how important the execution of this procedure is in the current playbook.
    priority: TestPriority = Field()
    # Foreign keys
    report_id: uuid.UUID | None = Field(foreign_key=("report.id"))
    section_id: uuid.UUID | None = Field(foreign_key=("testguidesection.id"))
    source_procedure_id: uuid.UUID | None = Field(foreign_key=("testprocedure.id"))
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Relationship definitions
    report: "Report" = Relationship(back_populates="procedures")
    section: "PlaybookSection" = Relationship(back_populates="procedures")
    vulnerabilities: List[Vulnerability] = Relationship(
        sa_relationship_kwargs=dict(
            cascade="all,delete,delete-orphan",
            order_by="desc(Vulnerability.severity), desc(Vulnerability.cvss_score)",
            back_populates="procedure"
        )
    )
    source_procedure: TestProcedure | None = Relationship(back_populates="report_procedures")
    files: List[File] = Relationship(
        sa_relationship_kwargs=dict(
            cascade="all",
            secondary="reportprocedurefile",
            back_populates="report_procedures"
        )
    )

    def get_vulnerability(self, vulnerability_id: uuid.UUID, must_exist: bool = False) -> Vulnerability | None:
        """
        Get the vulnerability associated with this procedure.
        """
        for vulnerability in self.vulnerabilities:
            if vulnerability.id == vulnerability_id:
                return vulnerability
        if must_exist:
            raise ValueError("Vulnerability not found.")
        return None

    def get_item(self, vulnerability_id: uuid.UUID) -> Vulnerability | None:
        try:
            return self.get_vulnerability(vulnerability_id, must_exist=True)
        except ValueError:
            ...
        return None

    def get_file(self, file_id: uuid.UUID) -> File | None:
        """
        Get the file with the given ID.
        """
        for file in self.files:
            if file.id == file_id:
                return file
        return None

    @staticmethod
    def clone_from_template(language, template, order: int, **kwargs):
        """
        Create an object based on the given TestProcedure object.
        """
        if not order:
            raise ValueError("Order attribute is mandatory.")
        return ReportProcedure(
            name=template.name,
            objective=template.get_objective(language),
            source_procedure=template,
            # TODO: Implement priority: this must be obtained from the m:n relationship object
            #       because it is Playbook specific.
            # priority=template.priority,
            priority=TestPriority.optional,
            order=order,
            **kwargs
        )


class ReportProcedureUpdateBase(BaseModel):
    """
    Schema for reading and updating a report procedures via FastAPI.
    """
    status: ReviewStatus
    internal_documentation: str | None = PydanticField(default=None)


class ReportProcedureUpdate(ReportProcedureUpdateBase):
    """
    Schema for updating a report procedures via FastAPI.
    """
    ...


class ReportProcedureRead(ReportProcedureUpdateBase):
    """
    Schema for reading a report procedures via FastAPI.
    """
    id: uuid.UUID
    name: str
    objective: str | None = PydanticField(default=None)
    source_procedure: TestProcedure | None = PydanticField(default=None, exclude=True)

    @computed_field
    def hints(self) -> str | None:
        return self.source_procedure.hints if self.source_procedure else None


class ReportProcedureTreeNode(SQLModel):
    id: uuid.UUID
    name: str
    status: ReviewStatus
    priority: TestPriority
    source_procedure_id: uuid.UUID | None = PydanticField(default=None)
    type: str = "procedure"
    vulnerabilities: List[Vulnerability] = PydanticField(default=[], exclude=True)
    # source_procedure: TestProcedure = PydanticField(exclude=True)

    @computed_field
    def children(self) -> List[VulnerabilityTreeNode]:
        return [
            VulnerabilityTreeNode(
                **item.model_dump()
            ) for item in self.vulnerabilities
        ]


class ReportProcedureReport(SQLModel):
    """
    Schema for creating the final JSON object based on which the report is created.
    """
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    status: ReviewStatus
    priority: TestPriority
    objective: str | None = PydanticField(default=None)
    source_procedure_id: uuid.UUID | None = PydanticField(default=None)
    vulnerabilities: List[VulnerabilityReport] = PydanticField(default=[])
