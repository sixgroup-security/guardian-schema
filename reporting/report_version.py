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
from typing import Dict
from sqlmodel import SQLModel, Field, Relationship
from sqlalchemy import Column, UniqueConstraint
from sqlalchemy.sql import func
from sqlalchemy.dialects import postgresql
from pydantic import BaseModel, Field as PydanticField, ConfigDict, computed_field
from schema.user import User, UserReport
from schema.reporting import ReportCreationStatus
from datetime import datetime, date

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class ReportVersionStatus(enum.IntEnum):
    draft = 0
    final = 10


class ReportVersion(SQLModel, table=True):
    """
    Store information about a report version in the database.
    """
    id: uuid.UUID = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    version: float = Field()
    username: str = Field()
    comment: str = Field()
    status: ReportVersionStatus = Field()
    report_date: date = Field(sa_column_kwargs=dict(server_default=func.now()))
    creation_status: ReportCreationStatus | None = Field()
    # Contains the current version as a JSON object
    json_object: Dict = Field(default={}, sa_column=Column(postgresql.JSON(), nullable=False))
    # Contains the current version as a PDF file
    pdf: bytes | None = Field()
    # Contains the current version as a Microsft Excel file
    xlsx: bytes | None = Field()
    # Contains the creation logs for the PDF file
    pdf_log: bytes | None = Field()
    # Contains the Latex source files for creating the PDF file
    tex: bytes | None = Field()
    # Foreign keys
    user_id: uuid.UUID = Field(foreign_key=("user.id"))
    report_id: uuid.UUID = Field(foreign_key=("report.id"))
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Relationship definitions
    report: "Report" = Relationship(back_populates="versions")
    user: User = Relationship(back_populates="report_versions")

    __table_args__ = (
        UniqueConstraint('report_id', 'version'),
    )


class ReportVersionUpdateBase(BaseModel):
    """
    Schema for reading and updating a report version via FastAPI.
    """
    version: float
    username: str
    comment: str
    status: ReportVersionStatus
    report_date: date


class ReportVersionRead(ReportVersionUpdateBase):
    """
    Schema for reading a report version via FastAPI.
    """
    id: uuid.UUID
    user: UserReport
    # json_object: Dict
    status: ReportVersionStatus
    creation_status: ReportCreationStatus | None = PydanticField(default=None)
    pdf: bytes | None = PydanticField(default=None, exclude=True)
    xlsx: bytes | None = PydanticField(default=None, exclude=True)
    pdf_log: bytes | None = PydanticField(default=None, exclude=True)
    tex: bytes | None = PydanticField(default=None, exclude=True)

    @computed_field
    def has_pdf(self) -> bool:
        return self.pdf is not None and len(self.pdf) > 0

    @computed_field
    def has_xlsx(self) -> bool:
        return self.xlsx is not None and len(self.xlsx) > 0

    @computed_field
    def has_pdf_log(self) -> bool:
        return self.pdf_log is not None and len(self.pdf_log) > 0

    @computed_field
    def has_tex(self) -> bool:
        return self.tex is not None and len(self.tex) > 0


class ReportVersionCreate(ReportVersionUpdateBase):
    """
    Schema for creating a new report version via FastAPI.
    """
    ...


class ReportVersionUpdate(ReportVersionUpdateBase):
    """
    Schema for updating an existing report version via FastAPI.
    """
    id: uuid.UUID


class ReportVersionReport(BaseModel):
    """
    Schema for creating the final JSON object based on which the report is created.
    """
    model_config = ConfigDict(from_attributes=True)
    version: float
    username: str
    comment: str
    status: ReportVersionStatus
    report_date: date

    @property
    def is_final(self) -> bool:
        """
        Check if the report version is final.
        """
        return self.status == ReportVersionStatus.final
