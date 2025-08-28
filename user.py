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

import os
import uuid
import enum
import base64
from datetime import date, datetime
from sqlmodel import Field, SQLModel, Column, Relationship
from sqlalchemy.sql import func
from typing import List, Set, Dict, Any, Optional
from schema.util import GuardianRoleEnum, EntityLookup, ROLE_PERMISSION_MAPPING, StatusMessage
from schema.entity import Entity
from schema.reporting.file import File
from schema.reporting.file.user import UserFile
from schema.project_user import ProjectAccess, ProjectTester
from schema.reporting.report_language import ReportLanguage, ReportLanguageLookup
from sqlalchemy import Enum, ForeignKey
from sqlalchemy.orm import Session
from sqlalchemy.dialects import postgresql
from pydantic import (
    BaseModel, ConfigDict, Field as PydanticField, AliasChoices, field_serializer, SerializationInfo,
    computed_field, field_validator
)

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class TokenType(enum.Enum):
    user = 10
    api = 20


class TableDensityType(enum.IntEnum):
    comfortable = 0
    standard = 10
    compact = 20


class UserType(enum.IntEnum):
    personal = 10
    technical = 20
    legacy = 30


class JsonWebToken(SQLModel, table=True):
    """
    Store information about a user tokens in the database.
    """
    id: uuid.UUID = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    name: str | None = Field()
    type: TokenType = Field()
    revoked: bool = Field(sa_column_kwargs=dict(server_default='false'))
    expiration: datetime | None = Field()
    value: str = Field(index=True, unique=True)
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(None, sa_column_kwargs=dict(onupdate=func.now()))
    # All relationship definitions
    user_id: uuid.UUID = Field(
        default=None,
        sa_column=Column(
            postgresql.UUID(as_uuid=True),
            ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False
        )
    )
    user: "User" = Relationship(back_populates="tokens")


class Notify(BaseModel):
    """
    This class is used to send users a notification.
    """
    subject: str
    message: str


class Notification(SQLModel, table=True):
    """
    Store information about a user's notifications.
    """
    id: uuid.UUID = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    subject: str = Field()
    message: str = Field()
    read: bool = Field(sa_column_kwargs=dict(server_default='false'))
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(None, sa_column_kwargs=dict(onupdate=func.now()))
    # All relationship definitions
    user_id: uuid.UUID = Field(
        default=None,
        sa_column=Column(postgresql.UUID(as_uuid=True), ForeignKey("user.id", ondelete="CASCADE"))
    )
    user: "User" = Relationship(back_populates="notifications")


class NotificationRead(BaseModel):
    """
    This is the notification schema. It is used by the FastAPI to read a notification.
    """
    id: uuid.UUID
    subject: str
    message: str
    read: bool
    created_at: datetime


class JsonWebTokenCreateUpdateBase(BaseModel):
    """
    Represents the base schema for updating or creating a JWT.
    """
    expiration: datetime | None = PydanticField(default=None, description="The expiration date and time of the token")


class JsonWebTokenCreate(JsonWebTokenCreateUpdateBase):
    """
    Schema for creating a JWT.
    """
    name: str = PydanticField(description="The name for the token")
    scope: List[str] = PydanticField(description="The access token's permissions")


class JsonWebTokenRead(JsonWebTokenCreateUpdateBase):
    """
    Schema for reading a JWT (without token value).
    """
    id: uuid.UUID
    name: str | None = PydanticField(default=None)
    revoked: bool
    created_at: datetime


class JsonWebTokenUpdate(BaseModel):
    """
    Scheme for updating a JWT.
    """
    id: uuid.UUID
    revoked: bool


class JsonWebTokenReadTokenValue(JsonWebTokenRead):
    """
    Schema for reading a JWT including token value.
    """
    value: str


class UserTest(BaseModel):
    """
    This is the user schema. It is used by pytest to create and manage test users during unittests.
    """
    id: uuid.UUID | None = PydanticField(None)
    email: str
    full_name: str
    bearer: str | None = PydanticField(None)
    roles: Set[GuardianRoleEnum]
    locked: bool | None | None = PydanticField(None)
    avatar: bytes | None = PydanticField(None)
    active_from: date | None = PydanticField(None)
    active_until: date | None | None = PydanticField(None)
    created_at: datetime | None = PydanticField(None)
    last_modified_at: datetime | None = PydanticField(None)
    last_login: datetime | None = PydanticField(None)
    provider_id: uuid.UUID | None = PydanticField(None)
    customer_id: uuid.UUID | None = PydanticField(None)

    @staticmethod
    def get_auth_header(bearer: str) -> Dict[str, str]:
        """
        Returns a cookie header with the bearer token.
        """
        return {'Cookie': f'access_token={bearer}'}

    @staticmethod
    def get_empty_auth_header() -> Dict[str, str]:
        return {'Cookie': f'access_token='}

    def get_authentication_header(self) -> Dict[str, str]:
        """
        Returns a cookie header with the bearer token.
        """
        return UserTest.get_auth_header(self.bearer)


class UserRead(BaseModel):
    """
    This is the user schema. It is used by the FastAPI to read a user.
    """
    model_config = ConfigDict(
        use_enum_values=False,
        extra="ignore",
        json_encoders={
            TableDensityType: lambda x: x.name
        }
    )

    id: uuid.UUID
    email: str
    full_name: str
    # username: str = Field()
    roles: Set[GuardianRoleEnum] | None = PydanticField(default={})
    locked: bool | None = PydanticField(default=None)
    show_in_dropdowns: bool | None = PydanticField(default=None)
    active_from: date | None = PydanticField(default=None)
    active_until: date | None = PydanticField(default=None)
    last_login: datetime | None = PydanticField(default=None)
    provider_id: EntityLookup | None = PydanticField(alias="provider")
    customer_id: EntityLookup | None = PydanticField(alias="customer")


class UserReport(BaseModel):
    """
    Schema for creating the final JSON object based on which the report is created.
    """
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    email: str
    full_name: str
    avatar: str | bytes | None = PydanticField(default=None)

    @field_serializer('avatar', when_used='json-unless-none')
    def serialize_avatar(self, avatar: bytes | None) -> str:
        return base64.b64encode(avatar).decode()

    @field_validator('avatar', mode='before')
    def validate_fields(cls, value: Any):
        """
        Method checks the type of the values and converts them if necessary.
        """
        if isinstance(value, str):
            return base64.b64decode(value)
        elif isinstance(value, bytes):
            return value
        else:
            return None

    def save_avatar(self, file_path: str) -> None:
        """
        Save the file to the specified path.
        """
        with open(os.path.join(file_path, f"{self.id}.png"), 'wb') as file:
            file.write(self.avatar)


class ReportRequestor(BaseModel):
    """
    Schema for sending requestor information to message queue.
    """
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    email: str
    full_name: str
    client_ip: str | None = PydanticField(default=None)


class NotifyUser(BaseModel):
    """
    Schema for notifying users via the message queue and WebSockets.
    """
    user: UserReport | ReportRequestor
    status: StatusMessage


class UserReadMe(UserRead):
    """
    This is the user schema. It is used by the FastAPI to read a user.
    """
    light_mode: bool
    toggle_menu: bool
    selected_year: int | None
    avatar: bytes | None = PydanticField(None, exclude=True)
    table_density: TableDensityType
    report_language: ReportLanguageLookup | None = Field(None)

    @computed_field
    def has_avatar(self) -> bool:
        return self.avatar is not None

    @field_serializer('selected_year')
    def serialize_selected_year(self, selected_year: int | str | None, _: SerializationInfo) -> str:
        return str(selected_year) if selected_year else "All"


class UserUpdateAdmin(SQLModel):
    """
    This is the user schema. It is used by the FastAPI to update a user.
    """
    model_config = ConfigDict(extra="ignore")

    id: uuid.UUID
    locked: bool | None = PydanticField(default=None)
    show_in_dropdowns: bool | None = PydanticField(default=None)
    active_from: date | None = PydanticField(default=None)
    active_until: date | None = PydanticField(default=None)
    provider_id: uuid.UUID | None = PydanticField(
        default=None,
        validation_alias=AliasChoices("provider", "provider_id")
    )
    customer_id: uuid.UUID | None = PydanticField(
        default=None,
        validation_alias=AliasChoices("customer", "customer_id")
    )


class User(SQLModel, table=True):
    """
    Store information about a user in the database.
    """
    id: uuid.UUID = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    email: str = Field(index=True, unique=True)
    locked: bool = Field(sa_column_kwargs=dict(server_default='false'))
    # Active directory username, if available
    # username: str = Field(unique=False)
    full_name: str = Field()
    type: UserType = Field(
        description="Defines the type of user account (e.g., personal for standard logins or technical for API keys)",
        sa_column_kwargs=dict(server_default=UserType.personal.name)
    )
    active_from: date = Field(sa_column_kwargs=dict(server_default=func.now()))
    active_until: date | None = Field()
    # Manage user settings
    light_mode: bool = Field(sa_column_kwargs=dict(server_default='true'))
    toggle_menu: bool = Field(sa_column_kwargs=dict(server_default='false'))
    table_density: TableDensityType = Field(sa_column_kwargs=dict(server_default=TableDensityType.compact.name))
    avatar: bytes | None = Field()
    selected_year: int | None = Field()
    roles: Set[GuardianRoleEnum] = Field(default={}, sa_column=Column(postgresql.ARRAY(Enum(GuardianRoleEnum))))
    # Allows setting whether the user should be displayed in any dropdown menus.
    show_in_dropdowns: bool = Field(sa_column_kwargs=dict(server_default='true'))
    # Contains the settings for DataGrids
    settings: Dict | None = Field(default={}, sa_column=Column(postgresql.JSON()))
    # Internal information only
    client_ip: str | None = Field(sa_column=Column(postgresql.INET, nullable=True))
    last_login: datetime | None = Field()
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # SIX-specific attributes
    user_name: str | None = Field(index=True, unique=True)  # Used to sync data from Guardian 1.0
    # Foreign keys
    report_language_id: uuid.UUID | None = Field(default=None, foreign_key="reportlanguage.id")
    provider_id: uuid.UUID | None = Field(default=None, foreign_key="entity.id")
    customer_id: uuid.UUID | None = Field(default=None, foreign_key="entity.id")
    # Relationship definitions
    report_language: ReportLanguage | None = Relationship(back_populates="users")
    tokens: List["JsonWebToken"] = Relationship(back_populates="user")
    notifications: List[Notification] = Relationship(
        sa_relationship_kwargs=dict(order_by="desc(Notification.created_at)"),
        back_populates="user"
    )
    project_permissions: List["Project"] = Relationship(back_populates="permissions", link_model=ProjectAccess)
    tests_projects: List["Project"] = Relationship(back_populates="testers", link_model=ProjectTester)
    leads_projects: List["Project"] = Relationship(
        back_populates="lead_tester",
        sa_relationship_kwargs=dict(foreign_keys="[Project.lead_tester_id]")
    )
    manages_projects: List["Project"] = Relationship(
        back_populates="manager",
        sa_relationship_kwargs=dict(foreign_keys="[Project.manager_id]")
    )
    files: List[File] = Relationship(back_populates="users", link_model=UserFile)
    provider: Entity | None = Relationship(
        sa_relationship_kwargs=dict(foreign_keys="[User.provider_id]"),
        back_populates="provider_users"
    )
    customer: Entity | None = Relationship(
        sa_relationship_kwargs=dict(foreign_keys="[User.customer_id]"),
        back_populates="customer_users"
    )
    report_versions: Optional["ReportVersion"] = Relationship(back_populates="user")
    comments: List["ProjectComment"] = Relationship(back_populates="user")
    responsible_for: List[Entity] = Relationship(
        sa_relationship_kwargs=dict(foreign_keys="[Entity.manager_id]"),
        back_populates="manager"
    )

    @property
    def roles_str(self) -> List[str]:
        return [item.name for item in self.roles]

    @property
    def scopes_str(self) -> List[str]:
        """
        Returns all REST API permissions/scopes.
        """
        result = []
        for role in self.roles:
            result.extend([item for item in ROLE_PERMISSION_MAPPING[role.name]])
        return list(set(sorted(result)))

    @property
    def is_active(self) -> bool:
        return not self.locked and \
               self.active_from <= date.today() and \
               (not self.active_until or self.active_until > date.today())

    def get_access_token(self, name: str):
        """
        Returns the user's access token by name.
        """
        result = [item for item in self.tokens if item.name == name and item.type == TokenType.api]
        if not result:
            return None
        return result[0]

    def notify(self, session: Session, message: Notify, dedup: bool = True):
        """
        Sends this user a notification.
        """
        unread_duplicates = [item for item in self.notifications if item.message == message and not item.read]
        if not dedup or len(unread_duplicates) == 0:
            session.add(Notification(**message.dict(), user_id=self.id))
        else:
            for item in unread_duplicates:
                item.created_at = func.now()
