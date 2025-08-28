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

import enum
import uuid
import inspect
from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlmodel import Field, SQLModel, Relationship, Column
from sqlalchemy import Enum, ForeignKey, UniqueConstraint
from pydantic import BaseModel, Field as PydanticField, ConfigDict, computed_field
from sqlalchemy.sql import func
from schema.util import ProjectType, multi_language_field_model_validator
from schema.reporting import TemplateStatus
from schema.reporting.file import File, FileReport
from schema.reporting.file.report_template import ReportTemplateFile
from schema.reporting.report_language import ReportLanguage, ReportLanguageLookup

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class ReportTemplateFileVersion(enum.IntEnum):
    v1 = 10


class ReportTemplateLanguage(SQLModel, table=True):
    """
    This is the schema for managing language-specific fields for measures.
    """
    id: Optional[uuid.UUID] = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    # TODO: Column status is in the wrong table. Move it to ReportTemplate
    status: TemplateStatus = Field(sa_column_kwargs=dict(server_default=TemplateStatus.draft.name))
    executive_summary: str = Field()
    prefix_section_text: str = Field()
    postfix_section_text: str = Field()
    # Describes how a single procedure description should look like.
    summary_template: Optional[str] = Field()
    # Foreign keys
    language_id: uuid.UUID = Field(foreign_key="reportlanguage.id")
    report_template_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("reporttemplate.id", ondelete="CASCADE"), nullable=False)
    )
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: Optional[datetime] = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # All relationship definitions
    # https://github.com/tiangolo/sqlmodel/issues/10
    language: ReportLanguage = (
        Relationship(
            sa_relationship_kwargs=dict(foreign_keys="[ReportTemplateLanguage.language_id]"),
            back_populates="report_template_details"
        )
    )
    report_template: "ReportTemplate" = (
        Relationship(
            sa_relationship_kwargs=dict(foreign_keys="[ReportTemplateLanguage.report_template_id]"),
            back_populates="multi_language_fields")
    )
    __table_args__ = (
        UniqueConstraint('language_id', 'report_template_id'),
    )


class ReportTemplate(SQLModel, table=True):
    """
    Store information about a report templates
    """
    id: Optional[uuid.UUID] = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    name: str = Field(index=True)
    project_type: ProjectType = Field(sa_column=Column(Enum(ProjectType), nullable=False))
    version: ReportTemplateFileVersion = Field(
        sa_column=Column(Enum(ReportTemplateFileVersion), server_default='v1', nullable=False)
    )
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: Optional[datetime] = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # All relationship definitions
    # https://github.com/tiangolo/sqlmodel/issues/10
    multi_language_fields: List[ReportTemplateLanguage] = Relationship(
        sa_relationship_kwargs=dict(cascade="all,delete,delete-orphan"),
        back_populates="report_template"
    )
    reports: List["Report"] = Relationship(back_populates="report_template")
    files: List[File] = Relationship(back_populates="report_templates", link_model=ReportTemplateFile)

    __table_args__ = (
        UniqueConstraint('name', 'project_type'),
    )

    def _get_language(self, language: ReportLanguage | ReportLanguageLookup, raise_not_found: bool = False) \
            -> Optional[ReportTemplateLanguage]:
        """
        Returns the correct TestProcedureLanguage object based on the given ReportLanguage object.
        """
        result = [item for item in self.multi_language_fields if item.language_id == language.id]
        if not result and raise_not_found:
            raise ValueError()
        return result[0] if result else None

    def get_executive_summary(self, language: ReportLanguage | ReportLanguageLookup,  default: str = None) -> str:
        result = self._get_language(language)
        return result.executive_summary if result else default

    def get_prefix_section_text(self, language: ReportLanguage | ReportLanguageLookup,  default: str = None) -> str:
        result = self._get_language(language)
        return result.prefix_section_text if result else default

    def get_postfix_section_text(self, language: ReportLanguage | ReportLanguageLookup,  default: str = None) -> str:
        result = self._get_language(language)
        return result.postfix_section_text if result else default

    def get_summary_template(self, language: ReportLanguage | ReportLanguageLookup,  default: str = None) -> str:
        result = self._get_language(language)
        return result.summary_template if result else default


class ReportTemplateCreateUpdateBase(BaseModel):
    """
    This is the base schema for updating or creating a report template.
    """
    name: str
    version: ReportTemplateFileVersion

    def __eq__(self, other: Any) -> bool:
        return self.name == other.name


class ReportTemplateCreate(ReportTemplateCreateUpdateBase):
    """
    This is the schema for creating, reading and updating a report template via FastAPI.
    """
    executive_summary: Dict[str, str]
    prefix_section_text: Dict[str, str]
    postfix_section_text: Dict[str, str]
    summary_template: Optional[Dict[str, str]]


class ReportTemplateUpdate(ReportTemplateCreate):
    """
    This is the schema for updating a report template via FastAPI.
    """
    id: uuid.UUID


class ReportTemplateRead(ReportTemplateCreateUpdateBase):
    """
    This is the schema for reading a report template via FastAPI.
    """
    model_config = ConfigDict(from_attributes=True, extra="ignore")

    id: uuid.UUID
    multi_language_fields: List[ReportTemplateLanguage] = PydanticField(exclude=True)

    @computed_field
    def executive_summary(self) -> Dict[str, str]:
        return multi_language_field_model_validator(self, inspect.currentframe())

    @computed_field
    def prefix_section_text(self) -> Dict[str, str]:
        return multi_language_field_model_validator(self, inspect.currentframe())

    @computed_field
    def postfix_section_text(self) -> Dict[str, str]:
        return multi_language_field_model_validator(self, inspect.currentframe())

    @computed_field
    def summary_template(self) -> Dict[str, str]:
        return multi_language_field_model_validator(self, inspect.currentframe())


class ReportTemplateResponse(ReportTemplateCreate):
    """
    This class can be used to parse the JSON response of measure GET, POST or PUT API operations.
    """
    id: uuid.UUID

    def __eq__(self, other: Any) -> bool:
        return (
            super().__eq__(other)
            and self.executive_summary == other.executive_summary
            and self.prefix_section_text == other.prefix_section_text
            and self.postfix_section_text == other.postfix_section_text
            and self.summary_template == other.summary_template
        )


class ReportTemplateLookup(SQLModel):
    id: uuid.UUID
    name: str


class ReportTemplateDetails(ReportTemplateLookup):
    summary_template: str | None = PydanticField(default="")


class ReportTemplateReport(SQLModel):
    """
    Schema for creating the final JSON object based on which the report is created.
    """
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    version: ReportTemplateFileVersion
    files: List[FileReport] = PydanticField(default=[])
