import enum
import uuid
from datetime import datetime
from pydantic import BaseModel, Field as PydanticField, AliasChoices, ConfigDict
from sqlmodel import Field, SQLModel, Relationship
from sqlalchemy.sql import func

from schema.util import ReportSectionLookup


class ReportScopeView(enum.IntEnum):
    internal = 10
    external = 20


class AssetType(enum.IntEnum):
    domain = 10
    email_address = 20
    hostname = 30
    ip_address = 40
    network_range = 50
    url = 60
    other = 70


class EnvironmentType(enum.IntEnum):
    development = 10
    testing = 20
    staging = 30
    integration = 40
    quality = 50
    production = 60


class ReportScope(SQLModel, table=True):
    """
    Store information about project scopes in the database.
    """
    id: uuid.UUID = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    view: ReportScopeView = Field()
    asset: str = Field()
    zone: str = Field()
    strong_authentication: bool | None = Field()
    type: AssetType = Field()
    description: str = Field()
    environment: EnvironmentType = Field()
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Foreign keys
    report_id: uuid.UUID = Field(foreign_key="report.id")
    report_section_id: uuid.UUID = Field(foreign_key="reportsection.id")
    # Relationship definitions
    report: "Report" = Relationship(back_populates="scopes")
    report_section: "ReportSection" = Relationship(back_populates="scopes")


class ReportScopeReadBase(BaseModel):
    asset: str
    zone: str
    strong_authentication: bool | None = Field(default=None)
    type: AssetType
    view: ReportScopeView
    description: str
    environment: EnvironmentType


class ReportScopeCreate(ReportScopeReadBase):
    """
    Schema for creating a new report scope.
    """
    report_section_id: uuid.UUID = PydanticField(alias="report_section")


class ReportScopeRead(ReportScopeReadBase):
    """
    Schema for creating a new report scope.
    """
    id: uuid.UUID
    report_section: ReportSectionLookup


class ReportScopeUpdate(ReportScopeCreate):
    """
    Schema for updating an existing report scope.
    """
    id: uuid.UUID
    report_section_id: uuid.UUID = PydanticField(validation_alias=AliasChoices("report_section", "report_section_id"))


class ReportScopeReport(BaseModel):
    """
    Schema for creating the final JSON object based on which the report is created.
    """
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    view: ReportScopeView
    asset: str = Field()
    zone: str = Field()
    strong_authentication: bool | None = PydanticField(default=None)
    type: AssetType = Field()
    description: str = Field()
    environment: EnvironmentType = Field()
