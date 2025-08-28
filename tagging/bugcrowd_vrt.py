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
from typing import List, Type
from pydantic import BaseModel, ConfigDict, Field as PydanticField, computed_field
from sqlmodel import Field, SQLModel, Relationship, Column, ForeignKey
from sqlalchemy import UniqueConstraint, and_
from sqlalchemy.sql import func
from sqlalchemy.orm import Session
from sqlalchemy.orm.query import Query
from datetime import datetime
from .cvss import Cvss
from schema.util import SeverityType
from .mitre_cwe import CweBase
from .vrt_cwe_mapping import VrtCweMapping

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class VrtCategory(SQLModel, table=True):
    """
    This class represents a VRT category.
    """
    id: UUID = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    vrt_id: str = Field(unique=True)
    name: str = Field(unique=True)
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Relationship definitions
    vrts: List["Vrt"] = Relationship(back_populates="category")
    # Internal information only
    release_date: datetime = Field()


class VrtSubCategory(SQLModel, table=True):
    """
    This class represents a specific vulnerability in a VRT.
    """
    id: UUID = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    vrt_id: str = Field(unique=True)
    name: str = Field(unique=True)
    # Internal information only
    release_date: datetime = Field()
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Relationship definitions
    vrts: List["Vrt"] = Relationship(back_populates="sub_category")


class VrtVariant(SQLModel, table=True):
    """
    This class represents a variant of an affected function in a VRT.
    """
    id: UUID = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    vrt_id: str = Field(unique=True)
    name: str = Field(unique=True)
    # Internal information only
    release_date: datetime = Field()
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Relationship definitions
    vrts: List["Vrt"] = Relationship(back_populates="variant")


class Vrt(SQLModel, table=True):
    """
    This class represents a VRT.
    """
    id: UUID = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    priority: int | None = Field()
    category_id: UUID = Field(
        sa_column=Column(ForeignKey("vrtcategory.id", ondelete="CASCADE"), nullable=False)
    )
    sub_category_id: UUID | None = Field(
        sa_column=Column(ForeignKey("vrtsubcategory.id", ondelete="CASCADE"))
    )
    variant_id: UUID | None = Field(
        sa_column=Column(ForeignKey("vrtvariant.id", ondelete="CASCADE"))
    )
    cvss_id: UUID | None = Field(
        sa_column=Column(ForeignKey("cvss.id", ondelete="CASCADE"))
    )
    # Internal information only
    release_date: datetime = Field()
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Relationship definitions
    vulnerabilities: List["Vulnerability"] = Relationship(back_populates="vrt")
    vulnerability_templates: List["VulnerabilityTemplate"] = Relationship(back_populates="vrt")
    cwes: List[CweBase] = Relationship(link_model=VrtCweMapping)
    category: VrtCategory = Relationship(back_populates="vrts")
    sub_category: VrtSubCategory = Relationship(back_populates="vrts")
    variant: VrtVariant = Relationship(back_populates="vrts")
    cvss: Cvss = Relationship(back_populates="vrt")

    __table_args__ = (
        UniqueConstraint(
            "category_id", "sub_category_id", "variant_id", "priority",
            postgresql_nulls_not_distinct=True
        ),
    )


class VrtRead(BaseModel):
    """
    Schema for reading the VRT data
    """
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    priority: int | None = PydanticField(default=None, exclude=True)
    category_id: UUID
    category: VrtCategory | None = PydanticField(default=None, exclude=True)
    sub_category: VrtSubCategory | None = PydanticField(default=None, exclude=True)
    variant: VrtVariant | None = PydanticField(default=None, exclude=True)
    cvss: Cvss | None = PydanticField(default=None, exclude=True)

    @computed_field
    def priority_str(self) -> str:
        return f"P{self.priority}" if self.priority else "Varies"

    @computed_field
    def category_name(self) -> str | None:
        return self.category.name if self.category else None

    @computed_field
    def sub_category_id(self) -> str | None:
        return self.sub_category.vrt_id if self.sub_category else None

    @computed_field
    def sub_category_name(self) -> str | None:
        return self.sub_category.name if self.sub_category else None

    @computed_field
    def variant_id(self) -> str | None:
        return self.variant.vrt_id if self.variant else None

    @computed_field
    def variant_name(self) -> str | None:
        return self.variant.name if self.variant else None

    @computed_field
    def cvss_base_score(self) -> float | None:
        return self.cvss.base_score if self.cvss else None

    @computed_field
    def cvss_base_vector(self) -> str | None:
        return self.cvss.base_vector if self.cvss else None

    @computed_field
    def cvss_base_severity(self) -> SeverityType | None:
        return self.cvss.base_severity if self.cvss else None

    @computed_field
    def label(self) -> str:
        result = []
        if self.category_name:
            result.append(self.category_name)
        if self.sub_category_name:
            result.append(self.sub_category_name)
        if self.variant_name:
            result.append(self.variant_name)
        return " / ".join(result)


class VrtReport(VrtRead):
    """
    Schema for creating the final JSON object based on which the report is created.
    """
    model_config = ConfigDict(from_attributes=True)
    ...


class VrtLookup(BaseModel):
    """
    This is the tag schema for looking up a VRT via FastAPI.
    """
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    category: VrtCategory = PydanticField(exclude=True)

    @computed_field
    def label(self) -> str:
        return self.category.name


class VrtVariantImport(BaseModel):
    """
    Loads VRT variants.
    """
    vrt_id: str = PydanticField(validation_alias="id")
    name: str
    type: str = PydanticField(pattern="^variant$")
    priority: int | None = PydanticField(default=None)


class VrtSubCategoryImport(BaseModel):
    """
    Loads VRT categories.
    """
    vrt_id: str = PydanticField(validation_alias="id")
    name: str
    type: str = PydanticField(pattern="^subcategory$")
    priority: int | None = PydanticField(default=None)
    children: List[VrtVariantImport] | None = PydanticField(default=[])


class VrtCategoryImport(BaseModel):
    """
    Loads the VRT category.
    """
    vrt_id: str = PydanticField(validation_alias="id")
    name: str
    priority: int | None = PydanticField(default=None)
    type: str = PydanticField(pattern="^category$")
    children: List[VrtSubCategoryImport] | None = PydanticField(default=[])


class VrtImport(BaseModel):
    """
    Loads the VRT content.
    """
    content: List[VrtCategoryImport]
    metadata: dict = PydanticField(default=None)

    @property
    def release_date(self) -> datetime:
        release_date = self.metadata.get("release_date")
        return datetime.fromisoformat(release_date)


def get_vrt(
        session: Session,
        category_id: str,
        sub_category_id: str | None,
        variant_id: str | None,
        priority: str | None
) -> Query[Type[Vrt]]:
    """
    Returns a VRT record based on the given data.
    """
    priority_filter = Vrt.priority == priority if priority else Vrt.priority.is_(None)
    if category_id and sub_category_id and variant_id:
        return session.query(Vrt) \
            .join(VrtCategory) \
            .join(VrtSubCategory) \
            .join(VrtVariant) \
            .filter(
                and_(
                    VrtCategory.vrt_id == category_id,
                    VrtSubCategory.vrt_id == sub_category_id,
                    VrtVariant.vrt_id == variant_id,
                    priority_filter
                )
            )
    elif category_id and sub_category_id:
        return session.query(Vrt) \
            .join(VrtCategory) \
            .join(VrtSubCategory) \
            .filter(
                and_(
                    VrtCategory.vrt_id == category_id,
                    VrtSubCategory.vrt_id == sub_category_id,
                    Vrt.variant_id.is_(None),
                    priority_filter
                )
            )
    elif category_id:
        return session.query(Vrt) \
            .join(VrtCategory) \
            .filter(
                and_(
                    VrtCategory.vrt_id == category_id,
                    Vrt.sub_category_id.is_(None),
                    Vrt.variant_id.is_(None),
                    priority_filter
                )
            )
    raise ValueError("Invalid VRT data.")
