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
from datetime import date, datetime
from pydantic import (
    BaseModel, ConfigDict, Field as PydanticField, AliasChoices, computed_field
)
from typing import List, Set, Any, Dict
from sqlmodel import Field, SQLModel, Relationship, UniqueConstraint
from sqlalchemy.sql import func
from schema.util import (
    ProjectType, UserLookup, ProjectTypePrefix, EntityLookup, NotFoundError
)
from schema.country import Country, CountryLookup, CountryReport
from schema.tagging import (
    TagProjectTestReason, TagProjectEnvironment, TagProjectGeneral, TagProjectClassification, Tag, TagLookup, TagReport
)
from schema.user import User, UserReport, ReportRequestor
from schema.reporting.report import Report, ReportReadLookup, ReportReport
from schema.entity import Entity, EntityReport
from schema.project_user import ProjectAccess, ProjectTester
from schema.project_comment import ProjectComment, ProjectCommentLookup
from schema.application import Application, ApplicationProject, ApplicationLookup, ApplicationReport

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class ProjectState(enum.IntEnum):
    backlog = 10
    planning = 20
    scheduled = 25
    running = 30
    reporting = 40
    completed = 50
    cancelled = 60
    archived = 70


class ReportRequestType(enum.IntEnum):
    """
    Defines the content of the report generation request.
    """
    report = enum.auto()
    vulnerability = enum.auto()


class Project(SQLModel, table=True):
    """
    Store information about a project in the database.
    """
    id: UUID | None = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    # project_type, year, and last_number are used to compile the project ID
    project_type: ProjectType = Field()
    year: int = Field()
    increment: int = Field()
    name: str = Field(index=True)
    state: ProjectState = Field(default=ProjectState.backlog)
    start_date: date = Field()
    end_date: date | None = Field()
    # The date when the project was marked as completed.
    completion_date: date | None = Field()
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Foreign keys
    lead_tester_id: UUID | None = Field(default=None, foreign_key="user.id")
    manager_id: UUID | None = Field(default=None, foreign_key="user.id")
    location_id: UUID = Field(foreign_key="country.id")
    provider_id: UUID | None = Field(default=None, foreign_key="entity.id")
    customer_id: UUID | None = Field(default=None, foreign_key="entity.id")
    # Relationship definitions
    permissions: List[User] = Relationship(back_populates="project_permissions", link_model=ProjectAccess)
    testers: List[User] = Relationship(back_populates="tests_projects", link_model=ProjectTester)
    reasons: List[Tag] = Relationship(back_populates="projects_reasons", link_model=TagProjectTestReason)
    environments: List[Tag] = Relationship(back_populates="projects_environment", link_model=TagProjectEnvironment)
    classifications: List[Tag] = Relationship(
        back_populates="projects_classification",
        link_model=TagProjectClassification
    )
    tags: List[Tag] = Relationship(back_populates="projects_general", link_model=TagProjectGeneral)
    # Additional applications to be tested by this project
    location: Country = Relationship(back_populates="projects")
    applications: List[Application] = Relationship(
        sa_relationship_kwargs=dict(order_by="asc(Application.name)"),
        back_populates="projects",
        link_model=ApplicationProject
    )
    manager: User | None = Relationship(
        back_populates="manages_projects",
        sa_relationship_kwargs=dict(foreign_keys="[Project.manager_id]")
    )
    lead_tester: User = Relationship(
        back_populates="leads_projects",
        sa_relationship_kwargs=dict(foreign_keys="[Project.lead_tester_id]")
    )
    reports: List[Report] = Relationship(back_populates="project")
    # https://github.com/tiangolo/sqlmodel/issues/10
    provider: Entity | None = Relationship(
        sa_relationship_kwargs=dict(foreign_keys="[Project.provider_id]"),
        back_populates="provider_projects"
    )
    customer: Entity | None = Relationship(
        sa_relationship_kwargs=dict(foreign_keys="[Project.customer_id]"),
        back_populates="customer_projects"
    )
    comments: List[ProjectComment] = Relationship(
        sa_relationship_kwargs=dict(
            cascade="all,delete,delete-orphan",
            order_by="desc(ProjectComment.created_at)"),
        back_populates="project"
    )

    __table_args__ = (
        UniqueConstraint('project_type', 'year', 'increment'),
    )

    @property
    def project_id(self) -> str:
        """
        Calculates the project ID.
        """
        return f"{ProjectTypePrefix[self.project_type.name].value}-{self.year}-{self.increment:03d}"

    def get_report(self, report_id: UUID, must_exist: bool = False) -> Report | None:
        """
        Get the report associated with this project.
        """
        for item in self.reports:
            if item.id == report_id:
                return item
        if must_exist:
            raise NotFoundError("Report not found.")
        return None

    def get_comment(self, comment_id: UUID, must_exist: bool = False) -> ProjectComment | None:
        """
        Get the report associated with this project.
        """
        for item in self.comments:
            if item.id == comment_id:
                return item
        if must_exist:
            raise NotFoundError("Comment not found.")
        return None

    def get_item(
            self,
            report_id: UUID = None,
            comment_id: UUID = None,
            report_version_id: UUID = None,
            report_file_id: UUID = None,
            report_section_id: UUID = None,
            playbook_id: UUID = None,
            playbook_section_id: UUID = None,
            procedure_id: UUID = None,
            vulnerability_id: UUID = None
    ):
        """
        Get the report section playbook associated with this project.
        """
        try:
            if comment_id:
                return self.get_comment(comment_id)
            report = self.get_report(report_id, must_exist=True)
            if report_section_id:
                return report.get_item(
                    report_section_id=report_section_id,
                    playbook_id=playbook_id,
                    playbook_section_id=playbook_section_id,
                    procedure_id=procedure_id,
                    vulnerability_id=vulnerability_id
                )
            elif report_version_id:
                return report.get_item(report_version_id=report_version_id)
            elif report_file_id:
                return report.get_item(report_file_id=report_file_id)
            return report
        except NotFoundError:
            ...
        return None


class ProjectCreateUpdateBase(SQLModel):
    """
    This is the project schema. It represents the base class for updating or creating a project.
    """
    model_config = ConfigDict(extra='ignore')

    name: str
    project_type: ProjectType
    state: ProjectState
    start_date: date
    end_date: date | None = Field(default=None)
    completion_date: date | None = Field(default=None)

    def __eq__(self, other: Any) -> bool:
        return (
            self.name == other.name and
            self.project_type == other.project_type and
            self.state == other.state and
            self.start_date == other.start_date and
            self.end_date == other.end_date and
            self.completion_date == other.completion_date
        )


class ProjectCreate(ProjectCreateUpdateBase):
    """
    This is the project schema. It is used by the FastAPI to create a project.
    """
    model_config = ConfigDict(extra="ignore")

    comment: str
    applications: Set[UUID] | None = PydanticField(default=[])
    testers: Set[UUID] | None = PydanticField(default=[])
    reasons: Set[UUID] | None = PydanticField(default=[])
    environments: Set[UUID] | None = PydanticField(default=[])
    classifications: Set[UUID] | None = PydanticField(default=[])
    tags: Set[UUID] | None = PydanticField(default=None)
    lead_tester_id: UUID | None = PydanticField(
        default=None,
        alias="lead_tester",
        validation_alias=AliasChoices("lead_tester", "lead_tester_id")
    )
    manager_id: UUID | None = PydanticField(
        default=None,
        alias="manager",
        validation_alias=AliasChoices("manager", "manager_id")
    )
    provider_id: UUID | None = PydanticField(
        default=None,
        alias="provider",
        validation_alias=AliasChoices("provider", "provider_id")
    )
    customer_id: UUID | None = PydanticField(
        default=None,
        alias="customer",
        validation_alias=AliasChoices("customer", "customer_id")
    )
    location_id: UUID = PydanticField(
        alias="location",
        validation_alias=AliasChoices("location", "location_id")
    )


class ProjectUpdate(ProjectCreate):
    """
    This is the project schema. It is used by the FastAPI to update a project.
    """
    id: UUID
    comment: str


class ProjectRead(ProjectCreateUpdateBase):
    """
    This is the project schema. It is used by the FastAPI to read a project.
    """
    id: UUID
    project_id: str
    applications: List[ApplicationLookup] | None = PydanticField(default=None)
    reasons: List[TagLookup] | None = PydanticField(default=[])
    environments: List[TagLookup] | None = PydanticField(default=[])
    classifications: List[TagLookup] | None = PydanticField(default=[])
    tags: List[TagLookup] | None = PydanticField(default=None)
    lead_tester_id: UserLookup | None = PydanticField(default=None, alias="lead_tester")
    manager_id: UserLookup | None = PydanticField(default=None, alias="manager")
    provider_id: EntityLookup | None = PydanticField(default=None, alias="provider")
    customer_id: EntityLookup | None = PydanticField(default=None, alias="customer")
    location_id: CountryLookup = PydanticField(default=None, alias="location")
    testers: List[UserLookup] | None = PydanticField(default=[])
    reports: List[ReportReadLookup]
    comments: List[ProjectCommentLookup]

    @computed_field
    def all_tags(self) -> List[TagLookup]:
        return self.classifications + self.reasons + self.environments + self.tags


class ProjectReport(SQLModel):
    """
    Schema for creating the final JSON object based on which the report is created.
    """
    model_config = ConfigDict(from_attributes=True)
    schema_version: str = "1.0"
    id: UUID
    project_id: str
    name: str
    project_type: ProjectType
    state: ProjectState
    start_date: date
    end_date: date | None = PydanticField(default=None)
    applications: List[ApplicationReport] | None = PydanticField(default=[])
    reasons: List[TagReport] | None = PydanticField(default=[])
    environments: List[TagReport] | None = PydanticField(default=[])
    classifications: List[TagReport] | None = PydanticField(default=[])
    tags: List[TagReport] | None = PydanticField(default=[])
    lead_tester: UserReport | None = PydanticField(default=[])
    manager: UserReport | None = PydanticField(default=None)
    provider: EntityReport | None = PydanticField(default=None)
    customer: EntityReport | None = PydanticField(default=None)
    location: CountryReport = PydanticField()
    testers: List[UserReport] | None = Field(default=[])
    report: ReportReport | None = PydanticField(default=None)

    def get_incomplete_fields(self) -> List[str]:
        """
        Returns a list of fields that are not set.
        """
        result = []
        if not self.end_date:
            result.append("End Date")
        if not self.reasons:
            result.append("Reasons")
        if not self.environments:
            result.append("Environments")
        if not self.lead_tester:
            result.append("Lead Tester")
        if not self.manager:
            result.append("Manager")
        if not self.provider:
            result.append("Provider")
        if not self.customer:
            result.append("Customer")
        return result


class ReportGenerationInfo(BaseModel):
    """
    Defines the content of a report generation request.
    """
    type: ReportRequestType
    vulnerabilities: List[UUID] | None = PydanticField(default=[])
    project: ProjectReport
    requestor: ReportRequestor | None = PydanticField(default=None)


def model_dump(item: ProjectCreate, exclude_unset: bool = True, **kwargs) -> Dict:
    """
    Pydantic model dump for the project.
    """
    return item.model_dump(exclude={
        "applications",
        "testers",
        "reasons",
        "environments",
        "classifications",
        "tags"
    }, exclude_unset=exclude_unset, **kwargs)
