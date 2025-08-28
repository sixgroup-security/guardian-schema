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

import enum
import sqlalchemy as sa
from uuid import UUID
from typing import List, Optional, Any
from pydantic import BaseModel, Field as PydanticField, ConfigDict, GetCoreSchemaHandler, computed_field
from pydantic_core import CoreSchema, core_schema
from sqlmodel import Relationship, Enum
from sqlmodel.main import default_registry
from sqlalchemy import Integer, Float, String, DateTime, ForeignKey, UniqueConstraint, Column
from sqlalchemy.sql import func
from sqlalchemy.orm import Mapped, mapped_column, backref, relationship
from datetime import datetime

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


Base = default_registry.generate_base()


class CweStatus(enum.IntEnum):
    draft = 10
    stable = 20
    deprecated = 30
    incomplete = 40


class CweVulnerabilityMappingType(enum.IntEnum):
    allowed = 10
    prohibited = 20
    discouraged = 30
    allowed_with_review = 40


class CweAbstractionType(enum.IntEnum):
    base = 10
    variant = 20
    class_ = 30
    pillar = 40
    compound = 50


class CweViewType(enum.IntEnum):
    graph = 10


class CweCategoryStatus(enum.IntEnum):
    draft = 10
    incomplete = 20
    obsolete = 30


class CweType(enum.IntEnum):
    base = 0
    weakness = 10
    category = 20
    view = 30


class CweNatureType(enum.IntEnum):
    child_of = 10
    member_of = 20
    member_of_primary = 25
    parent_of = 30
    depends_on = 40
    belongs_to = 50  # It is actually Has_Member and is used by categories. We changed it because in the
                     # CweRelationship table, the source is always the child (weakness) and we want to ensure
                     # consistency.


class CweOrdinalType(enum.IntEnum):
    primary = 10


class CweBase(Base):
    """
    This class represents a Common Weakness Enumeration (CWE) base entry.
    """
    __tablename__ = "cwebase"
    id: Mapped[UUID] = mapped_column(index=True, primary_key=True, server_default=func.gen_random_uuid())
    cwe_id: Mapped[int] = mapped_column(Integer, index=True)
    name: Mapped[str] = mapped_column(String, index=True)
    version: Mapped[float] = mapped_column(Float, nullable=True)
    mapping: Mapped[CweVulnerabilityMappingType] = mapped_column(
        Enum(CweVulnerabilityMappingType),
        nullable=False
    )
    cwe_type: Mapped[CweType] = mapped_column(Enum(CweType), nullable=False)
    # Internal information only
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)
    last_modified_at: Mapped[datetime] = mapped_column(DateTime, onupdate=func.now(), nullable=True)
    # vrts: List["Vrt"] = Relationship(
    #     sa_relationship_kwargs=dict(cascade="all", secondary="vrtcwemapping", back_populates="cwes")
    # )
    __mapper_args__ = {
        "polymorphic_identity": CweType.base,
        "polymorphic_on": "cwe_type"
    }

    @classmethod
    def __get_pydantic_core_schema__(
            cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        """
        This method is required to make the class processable by Pydantic.
        """
        return core_schema.no_info_after_validator_function(cls, handler(str))


class CweBaseRelationship(Base):
    """
    This class defines relationships between CWE base entries.
    """
    __tablename__ = "cwerelationship"
    id = Column(sa.UUID, index=True, primary_key=True, server_default=func.gen_random_uuid())
    source_id = Column(sa.UUID, ForeignKey('cwebase.id', ondelete='cascade'), nullable=False)
    destination_id = Column(sa.UUID, ForeignKey('cwebase.id', ondelete='cascade'), nullable=False)
    nature = Column(Enum(CweNatureType), nullable=False)
    ordinal: Mapped[CweOrdinalType] = mapped_column(
        Enum(CweOrdinalType),
        nullable=True
    )
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    last_modified_at = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    source = relationship(
        CweBase,
        backref=backref(
            'destination',
            cascade="delete, delete-orphan"
        ),
        primaryjoin="CweBaseRelationship.source_id == CweBase.id"
    )
    destination = relationship(
        CweBase,
        backref=backref(
            'source',
            cascade="delete, delete-orphan"
        ),
        primaryjoin="CweBaseRelationship.destination_id == CweBase.id"
    )
    __table_args__ = (
        UniqueConstraint("source_id", "destination_id"),
    )


class CweView(CweBase):
    """
    This class represents a Common Weakness Enumeration (CWE) view entry.
    """
    __tablename__ = "cweview"

    id: Mapped[UUID] = mapped_column(ForeignKey("cwebase.id"), index=True, primary_key=True)
    type: Mapped[CweViewType] = mapped_column(Enum(CweViewType), nullable=False)
    objective: Mapped[str]

    __mapper_args__ = {
        "polymorphic_identity": CweType.view
    }


class CweCategory(CweBase):
    """
    This class represents a Common Weakness Enumeration (CWE) category entry.
    """
    __tablename__ = "cwecategory"
    id: Mapped[UUID] = mapped_column(ForeignKey("cwebase.id"), index=True, primary_key=True)
    status: Mapped[CweCategoryStatus] = mapped_column(Enum(CweCategoryStatus), nullable=False)
    summary: Mapped[str] = mapped_column(String, nullable=False)
    __mapper_args__ = {
        "polymorphic_identity": CweType.category
    }


class CweWeakness(CweBase):
    """
    This class represents a Common Weakness Enumeration (CWE) entry.
    """
    __tablename__ = "cweweakness"
    id: Mapped[UUID] = mapped_column(ForeignKey("cwebase.id"), index=True, primary_key=True)
    status: Mapped[CweStatus] = mapped_column(Enum(CweStatus), nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=False)
    abstraction: Mapped[CweAbstractionType] = mapped_column(Enum(CweAbstractionType), nullable=False)
    __mapper_args__ = {
        "polymorphic_identity": CweType.weakness
    }

    @classmethod
    def __get_pydantic_core_schema__(
            cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        """
        This method is required to make the class processable by Pydantic.
        """
        return core_schema.no_info_after_validator_function(cls, handler(str))

    @staticmethod
    def _to_class(class_, source):
        """
        Method to convert data between Pydantic and SQLAlchemy objects.
        """
        return class_(
            id=source.id,
            cwe_id=source.id,
            name=source.name,
            version=source.version,
            mapping=source.mapping,
            cwe_type=source.cwe_type,
            status=source.status,
            description=source.description,
            abstraction=source.abstraction
        )


class CweLookup(BaseModel):
    """
    This is the tag schema for looking up a VRT via FastAPI.
    """
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    cwe_id: int = PydanticField()
    name: str = PydanticField(exclude=True)

    @computed_field
    def label(self) -> str:
        return f"CWE-{self.cwe_id} - {self.name}"


class CweReport(BaseModel):
    """
    Schema for creating the final JSON object based on which the report is created.
    """
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    cwe_id: int = PydanticField()
    name: str = PydanticField()

    @property
    def cwe_id_str(self) -> str:
        return f"CWE-{self.cwe_id}"

    @property
    def label(self) -> str:
        return f"CWE-{self.cwe_id} - {self.name}"
