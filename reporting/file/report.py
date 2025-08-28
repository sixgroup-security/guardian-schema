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
from typing import List
from sqlmodel import Field, SQLModel, Relationship
from sqlalchemy import ForeignKey, Column
from sqlalchemy.sql import func
from sqlalchemy.orm import backref
from schema.reporting.file import File

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class ReportFile(SQLModel, table=True):
    report_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("report.id", ondelete="CASCADE"), primary_key=True)
    )
    file_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("file.id", ondelete="CASCADE"), primary_key=True)
    )
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Relationship definitions
    report: List["Report"] = Relationship(
        sa_relationship_kwargs=dict(backref=backref("file_mappings",
                                                    cascade="delete, delete-orphan",
                                                    overlaps="reports,files"),
                                    overlaps="reports,files")
    )
    file: List["File"] = Relationship(
        sa_relationship_kwargs=dict(backref=backref("report_mappings",
                                                    cascade="delete, delete-orphan",
                                                    overlaps="reports,files"),
                                    overlaps="reports,files")
    )
