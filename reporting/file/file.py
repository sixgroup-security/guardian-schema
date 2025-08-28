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

import os
import enum
import uuid
import base64
import hashlib
from datetime import datetime
from typing import List
from pydantic import BaseModel, ConfigDict, Field as PydanticField, field_serializer, field_validator, computed_field
from sqlmodel import Field, SQLModel, Relationship
from schema.reporting.file.user import UserFile
from schema.reporting.file.test_procedure import TestProcedureFile
from sqlalchemy import INTEGER, Column, text
from sqlalchemy.schema import Sequence
from sqlalchemy.sql import func

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class FileSourceEnum(enum.IntEnum):
    report = enum.auto()
    report_template = enum.auto()
    test_procedure = enum.auto()
    vulnerability = enum.auto()


class File(SQLModel, table=True):
    """
    Store uploaded files.
    """
    id: uuid.UUID = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    # Simple ID (instead of UUID) for easier referencing the file in text.
    reference: int = Field(
        sa_column=Column(
            INTEGER,
            Sequence('file_ref_seq', increment=1),
            server_default=text("nextval('file_ref_seq')"),
            unique=True,
            autoincrement=True,
            nullable=False
        )
    )
    content: bytes = Field(nullable=False)
    content_type: str = Field()
    file_name: str = Field()
    sha256_value: str = Field(unique=True)
    source: FileSourceEnum = Field()
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Relationship definitions
    users: List["User"] = Relationship(back_populates="files", link_model=UserFile)
    reports: List["Report"] = Relationship(
        sa_relationship_kwargs=dict(cascade="all", secondary="reportfile", back_populates="files")
    )
    vulnerabilities: List["Vulnerability"] = Relationship(
        sa_relationship_kwargs=dict(cascade="all", secondary="vulnerabilityfile", back_populates="files")
    )
    report_procedures: List["ReportProcedure"] = Relationship(
        sa_relationship_kwargs=dict(cascade="all", secondary="reportprocedurefile", back_populates="files")
    )
    test_procedures: List["TestProcedure"] = Relationship(
        back_populates="files", link_model=TestProcedureFile
    )
    report_templates: List["ReportTemplate"] = Relationship(
        sa_relationship_kwargs=dict(cascade="all", secondary="reporttemplatefile", back_populates="files")
    )


class FileCreate(BaseModel):
    file_name: str
    content: bytes
    content_type: str
    source: FileSourceEnum

    @computed_field
    def sha256_value(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


class FileCreated(SQLModel):
    """
    This is the file schema. It is used by the FastAPI to return information about the newly created file.
    """
    id: uuid.UUID
    reference_int: int = PydanticField(exclude=True, validation_alias="reference")

    @computed_field
    def reference(self) -> str:
        return f"{self.reference_int:07d}"


class FileReport(SQLModel):
    """
    Schema for creating the final JSON object based on which the report is created.
    """
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    content: str | bytes | None = PydanticField(default=None)
    content_type: str
    file_name: str
    sha256_value: str

    @field_serializer("content", when_used='unless-none')
    def serialize_content(self, content: bytes | str) -> str:
        return base64.b64encode(content).decode() if isinstance(self.content, bytes) else self.content

    @field_validator('content')
    def validate_content(cls, content: bytes | str) -> bytes:
        return base64.b64decode(content) if isinstance(content, str) else content

    def save_to_file(self, file_path: str) -> None:
        """
        Save the file to the specified path.
        """
        with open(os.path.join(file_path, f"{self.id}.png"), 'wb') as file:
            file.write(self.content)
