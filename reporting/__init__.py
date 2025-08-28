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
from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel
from sqlalchemy.sql import func

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class TemplateStatus(enum.IntEnum):
    draft = 0
    review = 10
    final = 20


class ReportCreationStatus(enum.IntEnum):
    scheduled = 5
    generating = 10
    successful = 20
    failed = 30


class VulnerabilityBase(SQLModel):
    """
    Stores information that are common to template and test procedures.
    """
    id: uuid.UUID | None = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    references: str | None = Field()
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: Optional[datetime] = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Foreign keys
    vrt_id: uuid.UUID | None = Field(default=None, foreign_key="vrt.id")
    cwe_weakness_id: uuid.UUID | None = Field(default=None, foreign_key="cweweakness.id")
