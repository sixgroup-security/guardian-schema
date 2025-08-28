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


class AssetType(enum.IntEnum):
    hostname = enum.auto()
    ip_address = enum.auto()
    domain = enum.auto()
    url = enum.auto()
    critical_function = enum.auto()
    business_process = enum.auto()
    email_address = enum.auto()
    phone_number = enum.auto()
    username = enum.auto()


class EnvironmentType(enum.IntEnum):
    development = enum.auto()
    testing = enum.auto()
    staging = enum.auto()
    integration = enum.auto()
    pre_production = enum.auto()
    production = enum.auto()
    demo = enum.auto()
    training = enum.auto()
    performance = enum.auto()
    disaster_recovery = enum.auto()
    security_testing = enum.auto()


class ProjectScope(SQLModel, table=True):
    """
    Store information about project scopes in the database.
    """
    id: Optional[uuid.UUID] = Field(primary_key=True,
                                    index=True,
                                    sa_column_kwargs=dict(server_default=func.gen_random_uuid()))
    asset: str = Field()
    type: AssetType = Field()
    public: bool = Field(sa_column_kwargs=dict(server_default='false'))
    description: str = Field()
    environment: EnvironmentType = Field()
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: Optional[datetime] = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Foreign keys
    project_id: uuid.UUID = Field(default=None, foreign_key="project.id")
    # Relationship definitions
    # project: Optional["project"] = Relationship(back_populates="scope")
