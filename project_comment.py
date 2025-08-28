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

from uuid import UUID
from datetime import datetime
from sqlmodel import Field, SQLModel, Relationship
from pydantic import BaseModel, Field as PydanticField, field_serializer, field_validator
from sqlalchemy.sql import func
from schema.util import UserLookup, serialize_uuids, validate_uuids
from schema.user import User

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class ProjectComment(SQLModel, table=True):
    id: UUID | None = Field(primary_key=True,
                            index=True,
                            sa_column_kwargs=dict(server_default=func.gen_random_uuid()))
    project_id: UUID = Field(
        foreign_key="project.id",
    )
    user_id: UUID = Field(
        foreign_key="user.id",
    )
    comment: str = Field()
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Relationship definitions
    user: User = Relationship(back_populates="comments")
    project: "Project" = Relationship(back_populates="comments")


class ProjectCommentLookup(BaseModel):
    id: UUID
    user_id: UserLookup = PydanticField(alias="user")
    comment: str
    created_at: datetime

    @field_serializer('id', when_used='json')
    def serialize_id(self, attribute: UUID) -> str:
        return serialize_uuids(attribute)


class ProjectCommentUpdate(BaseModel):
    id: UUID
    comment: str

    @field_serializer('id', when_used='json')
    def serialize_id(self, attribute: UUID) -> str:
        return serialize_uuids(attribute)

    @field_validator('id', mode='before')
    def validate_uuids(cls, attribute: UUID | str) -> UUID:
        """
        Validate the UUIDs.
        """
        return validate_uuids(attribute)
