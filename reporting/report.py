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
from pydantic import BaseModel, Field as PydanticField, ConfigDict, computed_field, AliasChoices, field_serializer
from sqlmodel import Field, SQLModel, Relationship, Column
from sqlalchemy import Enum, UniqueConstraint
from sqlalchemy.sql import func
from schema.reporting.file import File, FileReport
from schema.reporting.report_version import ReportVersion, ReportVersionReport, ReportVersionStatus
from schema.reporting.report_section_management.report_section import (
    ReportSection, ReportSectionTreeNode, ReportSectionReport
)
from schema.reporting.report_template import (
    ReportTemplate, ReportTemplateDetails, ReportTemplateLookup, ReportTemplateReport, ReportTemplateFileVersion
)
from schema.reporting.report_language import ReportLanguage, ReportLanguageLookup, ReportLanguageReport
from schema.reporting.report_section_management.report_procedure import ReportProcedure
from schema.reporting.report_scope import ReportScope, ReportScopeReport

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class Report(SQLModel, table=True):
    """
    Store information about a report templates
    """
    id: uuid.UUID | None = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    version: ReportTemplateFileVersion = Field(
        sa_column=Column(Enum(ReportTemplateFileVersion), server_default='v1', nullable=False)
    )
    executive_summary: str | None = Field()
    prefix_section_text: str | None = Field()
    postfix_section_text: str | None = Field()
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Foreign keys
    project_id: uuid.UUID = Field(foreign_key="project.id")
    report_template_id: uuid.UUID = Field(foreign_key="reporttemplate.id")
    report_language_id: uuid.UUID = Field(foreign_key="reportlanguage.id")
    # All relationship definitions
    # https://github.com/tiangolo/sqlmodel/issues/10
    project: "Project" = Relationship(
        sa_relationship_kwargs=dict(foreign_keys="[Report.project_id]"),
        back_populates="reports"
    )
    report_template: ReportTemplate = Relationship(
        sa_relationship_kwargs=dict(foreign_keys="[Report.report_template_id]"),
        back_populates="reports"
    )
    report_language: ReportLanguage = Relationship(
        sa_relationship_kwargs=dict(foreign_keys="[Report.report_language_id]"),
        back_populates="reports"
    )
    sections: List[ReportSection] = Relationship(
        sa_relationship_kwargs=dict(cascade="all,delete,delete-orphan", order_by="asc(ReportSection.order)"),
        back_populates="report"
    )
    procedures: List[ReportProcedure] = Relationship(back_populates="report")
    versions: List[ReportVersion] = Relationship(
        back_populates="report",
        sa_relationship_kwargs=dict(order_by="asc(ReportVersion.version)")
    )
    files: List[File] = Relationship(
        sa_relationship_kwargs=dict(cascade="all", secondary="reportfile", back_populates="reports")
    )
    scopes: List[ReportScope] = Relationship(back_populates="report")

    __table_args__ = (
        UniqueConstraint('project_id', 'report_template_id', 'report_language_id'),
    )

    def get_section(self, report_section_id: uuid.UUID, must_exist: bool = False) -> ReportSection | None:
        """
        Get the section associated with this report.
        """
        for section in self.sections:
            if section.id == report_section_id:
                return section
        if must_exist:
            raise ValueError("Report section not found.")
        return None

    def get_version(self, report_version_id: uuid.UUID, must_exist: bool = False) -> ReportVersion | None:
        """
        Get the version associated with this report.
        """
        for version in self.versions:
            if version.id == report_version_id:
                return version
        if must_exist:
            raise ValueError("Report version not found.")
        return None

    def get_latest_final_version(self) -> ReportVersion | None:
        """
         Get the latest final version of this report.
        """
        result = [item for item in self.versions if item.status == ReportVersionStatus.final]
        return result[-1] if result else None

    def get_file(self, file_id: uuid.UUID) -> File | None:
        """
        Get the file associated with this report.
        """
        for file in self.files:
            if file.id == file_id:
                return file
        return None

    def get_scope(self, scope_id: uuid.UUID) -> ReportScope | None:
        """
        Get the report scope associated with this report.
        """
        for scope in self.scopes:
            if scope.id == scope_id:
                return scope
        return None

    def get_item(
            self,
            report_version_id: uuid.UUID = None,
            report_file_id: uuid.UUID = None,
            report_section_id: uuid.UUID = None,
            playbook_id: uuid.UUID = None,
            playbook_section_id: uuid.UUID = None,
            procedure_id: uuid.UUID = None,
            vulnerability_id: uuid.UUID = None
    ):
        try:
            if report_version_id:
                return self.get_version(report_version_id)
            elif report_file_id:
                return self.get_file(report_file_id)
            report_section = self.get_section(report_section_id, must_exist=True)
            if playbook_id or vulnerability_id:
                return report_section.get_item(
                    playbook_id=playbook_id,
                    playbook_section_id=playbook_section_id,
                    procedure_id=procedure_id,
                    vulnerability_id=vulnerability_id
                )
            return report_section
        except ValueError:
            ...
        return None


class ReportCreateUpdateBase(BaseModel):
    """
    This is the report schema for creating, reading and updating a report via FastAPI.
    """
    report_language_id: uuid.UUID = PydanticField(
        serialization_alias="report_language",
        validation_alias=AliasChoices("report_language", "report_language_id")
    )
    report_template_id: uuid.UUID = PydanticField(
        serialization_alias="report_template",
        validation_alias=AliasChoices("report_template", "report_template_id")
    )


class ReportCreate(ReportCreateUpdateBase):
    """
    This is the report schema for creating a report via FastAPI.
    """
    # We do not specify executive_summary, prefix_section_text, postfix_section_text as they are options from the
    # report template.
    ...


class ReportGeneralRead(BaseModel):
    """
    Base schema for reading report data.
    """
    id: uuid.UUID
    project: Any = PydanticField(exclude=True)

    @computed_field
    def project_name(self) -> str:
        return self.project.name

    @computed_field
    def project_id(self) -> str:
        """
        Returns the project ID in human-readable format.
        """
        return self.project.project_id


class ReportUpdate(BaseModel):
    """
    This is the report schema for updating a report via FastAPI.
    """
    id: uuid.UUID
    version: ReportTemplateFileVersion
    executive_summary: str
    prefix_section_text: str
    postfix_section_text: str


class ReportMainRead(ReportGeneralRead, ReportUpdate):
    """
    Report schema for reading the report content
    """
    ...


class ReportOverviewRead(ReportGeneralRead):
    """
    Report schema for reading the report overview information
    """
    report_language: ReportLanguageLookup
    report_template: ReportTemplate = PydanticField(exclude=True)

    @computed_field
    def report_template_details(self) -> ReportTemplateDetails:
        template_summary = self.report_template.get_summary_template(self.report_language)
        return ReportTemplateDetails(**self.report_template.model_dump(), summary_template=template_summary)


class ReportTestingRead(ReportOverviewRead):
    """
    Report schema for reading the report testing information
    """
    sections: List[ReportSection] = PydanticField(default=[], exclude=True)

    @computed_field
    def structure(self) -> List[ReportSectionTreeNode]:
        result = [
            ReportSectionTreeNode(
                **item.model_dump(),
                playbooks=item.playbooks,
                vulnerabilities=item.vulnerabilities
            ) for item in self.sections
        ]
        return result


class ReportReadLookup(SQLModel):
    id: uuid.UUID
    report_template: ReportTemplateLookup = PydanticField()
    report_language: ReportLanguageLookup = PydanticField()

    @computed_field
    def has_pdf(self) -> bool:
        return True

    @computed_field
    def has_xlsx(self) -> bool:
        return True


class ReportResponse(ReportCreate):
    id: uuid.UUID
    version: ReportTemplateFileVersion
    executive_summary: str | None
    prefix_section_text: str | None
    postfix_section_text: str | None
    project_id: uuid.UUID

    def __eq__(self, other: Any) -> bool:
        return (
            self.id == other.id
            and self.version == other.version
            and self.executive_summary == other.executive_summary
            and self.prefix_section_text == other.prefix_section_text
            and self.postfix_section_text == other.postfix_section_text
            and self.project_id == other.project_id
            and self.report_language_id == other.report_language_id
            and self.report_template_id == other.report_template_id
        )


class ReportReport(SQLModel):
    """
    Schema for creating the final JSON object based on which the report is created.
    """
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    version: ReportTemplateFileVersion
    executive_summary: str
    prefix_section_text: str
    postfix_section_text: str
    versions: List[ReportVersionReport] = PydanticField(default=[])
    report_template: ReportTemplateReport
    report_language: ReportLanguageReport
    files: List[FileReport] = PydanticField(default=[])
    sections: List[ReportSectionReport] = PydanticField(default=[])
    scopes: List[ReportScopeReport] = PydanticField(default=[])

    @field_serializer('sections')
    def filter_hidden_sections(self, sections: List[ReportSectionReport]):
        """
        We only serialize sections that are not marked as hidden.
        """
        return [section for section in sections if not section.hide]

    @property
    def severity_distribution_list(self) -> List[int]:
        """
        Get the distribution of vulnerabilities by severity.
        :return: List of four integers representing the number of vulnerabilities per severity.
        The order is: critical, high, medium, low.
        """
        result = [0, 0, 0, 0]
        for section in self.sections:
            if section.visible:
                distribution = section.severity_distribution_list
                if len(result) != len(distribution):
                    raise ValueError("The severity distribution is not complete.")
                result = [result[i] + distribution[i] for i in range(len(result))]
        return result
