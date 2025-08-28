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
from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel, Column
from sqlalchemy import ForeignKey
from sqlalchemy.sql import func

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class VrtCweMapping(SQLModel, table=True):
    cwe_base_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("cwebase.id", ondelete="CASCADE"), primary_key=True)
    )
    vrt_id: uuid.UUID = Field(
        sa_column=Column(ForeignKey("vrt.id", ondelete="CASCADE"), primary_key=True)
    )
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: Optional[datetime] = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Relationship definitions
    # vrt: List["Vrt"] = Relationship(
    #     sa_relationship_kwargs=dict(
    #         backref=backref(
    #             "vrt_crt_mappings", cascade="delete, delete-orphan", overlaps="vrts,cwes"
    #         ),
    #         overlaps="vrts,cwes"
    #     )
    # )
    # cwe: List[CweBase] = Relationship(
    #     sa_relationship_kwargs=dict(
    #         backref=backref(
    #             "vrt_crt_mappings", cascade="delete, delete-orphan", overlaps="vrts,cwes"
    #         ),
    #         overlaps="report_templates,files"
    #     )
    # )
