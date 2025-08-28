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
from typing import Dict, Optional, List
from sqlmodel import Field, SQLModel, Relationship, Column
from sqlalchemy import UniqueConstraint, ForeignKey
from sqlalchemy.sql import func
from schema.reporting.report_section_management.playbook_section import (
    PlaybookSection, PlaybookSectionTreeNode, PlaybookSectionReport
)
from pydantic import BaseModel, Field as PydanticField, ConfigDict, computed_field

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class ReportSectionPlaybook(SQLModel, table=True):
    """
    Store and manage report section playbook information.
    """
    __tablename__ = "reportsectiontestguide"
    id: uuid.UUID = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    name: str = Field()
    order: int = Field()
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Foreign keys
    section_id: uuid.UUID = Field(
        sa_column=Column(
            ForeignKey("reportsection.id", ondelete="CASCADE"),
            nullable=False
        )
    )
    playbook_id: uuid.UUID = Field(
        sa_column=Column(
            ForeignKey("testguide.id"),
            name="test_guide_id",
            nullable=False
        )
    )
    # Relationship definitions
    section: "ReportSection" = Relationship(back_populates="playbooks")
    playbook_sections: List[PlaybookSection] = Relationship(
        sa_relationship_kwargs=dict(
            cascade="all,delete,delete-orphan",
            order_by="asc(PlaybookSection.order)",
            back_populates="playbook",
        )
    )

    __table_args__ = (
        UniqueConstraint('section_id', 'test_guide_id'),
    )

    def get_section(self, section_id: uuid.UUID) -> Optional["PlaybookSection"]:
        """
        Get the section associated with this playbook.
        """
        for section in self.playbook_sections:
            result = section.get_section(section_id)
            if result:
                return result
        return None

    def get_item(
        self,
        playbook_section_id: uuid.UUID = None,
        procedure_id: uuid.UUID = None,
        vulnerability_id: uuid.UUID = None
    ):
        try:
            playbook_section = self.get_section(playbook_section_id)
            if procedure_id:
                return playbook_section.get_item(procedure_id=procedure_id, vulnerability_id=vulnerability_id)
            return playbook_section
        except ValueError:
            ...
        return None


class ReportSectionPlaybookCreateUpdateBase(BaseModel):
    """
    This is the base schema for updating or creating report sections.
    """
    name: str
    structure: Dict


class ReportSectionPlaybookCreate(ReportSectionPlaybookCreateUpdateBase):
    """
    This is the schema for creating a report section via FastAPI.
    """
    ...


class ReportSectionPlaybookUpdate(ReportSectionPlaybookCreateUpdateBase):
    """
    This is the schema for creating a report section via FastAPI.
    """
    id: uuid.UUID


class ReportSectionPlaybookTreeNode(BaseModel):
    id: uuid.UUID
    type: str = "playbook"
    name: str = PydanticField(exclude=True)
    order: int = PydanticField(exclude=True)
    playbook_sections: List[PlaybookSection] = PydanticField(default=[], exclude=True)

    @computed_field
    def info(self) -> Dict[str, str | int]:
        return {
            "name": self.name,
            "order": self.order
        }

    @computed_field
    def children(self) -> List[PlaybookSectionTreeNode]:
        return [
            PlaybookSectionTreeNode(
                **item.model_dump(),
                children=item.children,
                procedures=item.procedures
            ) for item in self.playbook_sections
        ]


class ReportSectionPlaybookReport(BaseModel):
    """
    Schema for creating the final JSON object based on which the report is created.
    """
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    playbook_sections: List[PlaybookSectionReport] = PydanticField(default=[])
