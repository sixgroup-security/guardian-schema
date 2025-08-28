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
from datetime import date, datetime
from sqlmodel import Field, SQLModel, Column, Relationship
from sqlalchemy import UniqueConstraint
from sqlalchemy.sql import func
from sqlalchemy.orm import backref
from typing import Set
from sqlalchemy import Enum
from sqlalchemy.dialects import postgresql

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class PermissionEnum(enum.IntEnum):
    read = enum.auto()
    create = enum.auto()
    modify = enum.auto()


class ProjectAccess(SQLModel, table=True):
    project_id: uuid.UUID = Field(
        foreign_key="project.id",
        primary_key=True
    )
    user_id: uuid.UUID = Field(
        foreign_key="user.id",
        primary_key=True
    )
    permissions: Set[PermissionEnum] = Field(default={}, sa_column=Column(postgresql.ARRAY(Enum(PermissionEnum))))
    disabled: bool = Field(sa_column_kwargs=dict(server_default='false'))
    active_from: date = Field(sa_column_kwargs=dict(server_default=func.now()))
    active_until: date | None = Field()
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # All relationship definitions
    project: "Project" = Relationship(
        sa_relationship_kwargs=dict(backref=backref("project_permissions_links",
                                                    cascade="delete, delete-orphan",
                                                    overlaps="permissions,project_permissions"),
                                    overlaps="permissions,project_permissions"))
    user: "User" = Relationship(
        sa_relationship_kwargs=dict(backref=backref("project_permissions_links",
                                                    cascade="delete, delete-orphan",
                                                    overlaps="permissions,project_permissions"),
                                    overlaps="permissions,project_permissions"))

    @property
    def is_active(self) -> bool:
        return not self.disabled and \
            self.active_from <= date.today() and \
            (not self.active_until or self.active_until > date.today())


class ProjectAccessRead(SQLModel):
    project_id: uuid.UUID
    user_id: uuid.UUID
    permissions: Set[PermissionEnum]
    disabled: bool
    active_from: date
    active_until: date | None


class ProjectAccessUpdate(SQLModel):
    permissions: Set[PermissionEnum] | None
    disabled: bool | None
    active_from: date | None
    active_until: date | None


class ProjectAccessCreate(ProjectAccessUpdate):
    user_id: uuid.UUID


class ProjectTester(SQLModel, table=True):
    project_id: uuid.UUID = Field(
        default=None,
        foreign_key="project.id",
        primary_key=True
    )
    user_id: uuid.UUID = Field(
        default=None,
        foreign_key="user.id",
        primary_key=True
    )
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))


class ProjectTesterRead(SQLModel):
    project_id: uuid.UUID
    user_id: uuid.UUID
    lead_tester: bool


class ProjectTesterUpdate(SQLModel):
    lead_tester: bool


class ProjectTesterCreate(ProjectTesterUpdate):
    user_id: uuid.UUID
