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
from sqlmodel import Field, Relationship, Column, ForeignKey
from sqlalchemy import UniqueConstraint
from sqlalchemy.sql import func
from pydantic import BaseModel, ConfigDict, Field as PydanticField, computed_field, field_serializer
from schema.util import SeverityType
from schema.reporting.report_scope import ReportScope
from schema.reporting.report_section_management import SectionStatistics
from schema.reporting.report_section_management.vulnerability import (
    Vulnerability, VulnerabilityTreeNode, VulnerabilityReport, VulnerabilityStatus
)
from schema.reporting.report_section_management.report_section_playbook import (
    ReportSectionPlaybook, ReportSectionPlaybookTreeNode, ReportSectionPlaybookReport
)

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class ReportSection(SectionStatistics, table=True):
    """
    Store and manage report section information.
    """
    id: uuid.UUID = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    name: str = Field()
    order: int = Field()
    hide: bool = Field(sa_column_kwargs=dict(server_default='false'))
    description: str | None = Field()
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: Optional[datetime] = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Foreign keys
    report_id: uuid.UUID = Field(sa_column=Column(ForeignKey("report.id"), nullable=False))
    # Relationship definitions
    report: "Report" = Relationship(back_populates="sections")
    vulnerabilities: List[Vulnerability] = Relationship(
        sa_relationship_kwargs=dict(
            cascade="all,delete,delete-orphan",
            order_by="asc(Vulnerability.vulnerability_id)",
            back_populates="report_section")
    )
    playbooks: List[ReportSectionPlaybook] = (
        Relationship(sa_relationship_kwargs=dict(cascade="all,delete,delete-orphan",
                                                 order_by="asc(ReportSectionPlaybook.order)",
                                                 back_populates="section"))
    )
    scopes: List[ReportScope] = Relationship(back_populates="report_section")

    __table_args__ = (
        UniqueConstraint('report_id', 'name'),
    )

    def get_playbook(self, playbook_id: uuid.UUID, must_exist: bool = False) -> Optional[ReportSectionPlaybook]:
        """
        Get the playbook associated with this report section.
        """
        for playbook in self.playbooks:
            if playbook.id == playbook_id:
                return playbook
        if must_exist:
            raise ValueError("Playbook not found.")
        return None

    def get_vulnerability(self, vulnerability_id: uuid.UUID, must_exist: bool = False) -> Optional[Vulnerability]:
        """
        Get the vulnerability associated with this report section.
        """
        for vulnerability in self.vulnerabilities:
            if vulnerability.id == vulnerability_id:
                return vulnerability
        if must_exist:
            raise ValueError("Vulnerability not found.")
        return None

    def get_item(
            self,
            playbook_id: uuid.UUID = None,
            playbook_section_id: uuid.UUID = None,
            procedure_id: uuid.UUID = None,
            vulnerability_id: uuid.UUID = None
    ):
        try:
            if playbook_id:
                playbook = self.get_playbook(playbook_id, must_exist=True)
                if playbook_section_id:
                    return playbook.get_item(
                        playbook_section_id=playbook_section_id,
                        procedure_id=procedure_id,
                        vulnerability_id=vulnerability_id
                    )
                return playbook
            elif vulnerability_id:
                return self.get_vulnerability(vulnerability_id, must_exist=True)
        except ValueError:
            ...
        return None


class ReportSectionCreateUpdateBase(BaseModel):
    """
    This is the base schema for updating or creating report sections.
    """
    name: str
    description: Optional[str]


class ReportSectionCreate(ReportSectionCreateUpdateBase):
    """
    This is the schema for creating a report section via FastAPI.
    """
    ...


class ReportSectionUpdate(ReportSectionCreateUpdateBase):
    """
    This is the schema for creating a report section via FastAPI.
    """
    id: uuid.UUID
    hide: bool


class ReportSectionTreeNode(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    type: str = "reportSection"
    name: str = PydanticField(exclude=True)
    order: int = PydanticField(exclude=True)
    hide: bool = PydanticField(exclude=True)
    description: str | None = PydanticField(exclude=True)
    playbooks: List[ReportSectionPlaybook] = PydanticField(default=[], exclude=True)
    vulnerabilities: List[Vulnerability] = PydanticField(default=[], exclude=True)

    @computed_field
    def info(self) -> Dict[str, str | int]:
        result = {
            "name": self.name,
            # We need to provide the order to the front-end, else the TreeView will not render correctly.
            "order": self.order,
            "hide": self.hide,
            "description": self.description
        }
        return result

    @computed_field
    def children(self) -> List[ReportSectionPlaybookTreeNode | VulnerabilityTreeNode]:
        result = [
            ReportSectionPlaybookTreeNode(**item.model_dump(), playbook_sections=item.playbook_sections) for
            item in self.playbooks
        ]
        # Include custom vulnerabilities directly linked to the report section
        result += [VulnerabilityTreeNode(**item.model_dump()) for item in self.vulnerabilities if not item.procedure_id]
        return result


class ReportSectionReport(BaseModel):
    """
    Schema for creating the final JSON object based on which the report is created.
    """
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    hide: bool | None = PydanticField(default=False)
    description: str | None = PydanticField(default=None)
    playbooks: List[ReportSectionPlaybookReport] = PydanticField(default=[])
    vulnerabilities: List[VulnerabilityReport] = PydanticField(default=[])

    @field_serializer('vulnerabilities')
    def filter_incomplete_vulnerabilities(self, vulnerabilities: List[VulnerabilityReport]):
        """
        We only serialize sections that are complete and have all mandatory fields populated.
        """
        # Lookup: Check Report Version
        return [
            vulnerability for vulnerability in vulnerabilities if vulnerability.status in [
                VulnerabilityStatus.final, VulnerabilityStatus.review, VulnerabilityStatus.resolved
            ]
        ]

    @property
    def visible(self) -> bool:
        """
        Check if the report section should be shown.
        """
        return True

    @staticmethod
    def severities() -> List[SeverityType]:
        """
        Get the severity types.
        """
        return sorted(
            [item for item in SeverityType if item != SeverityType.info],
            key=lambda x: x.value,
            reverse=True
        )

    @property
    def severity_distribution_list(self) -> List[int]:
        """
        Get the distribution of vulnerabilities by severity.
        :return: List of four integers representing the number of vulnerabilities per severity.
        The order is: critical, high, medium, low.
        """
        severities = self.severities()
        result = {item.name: 0 for item in severities}
        for item in self.vulnerabilities:
            if item.visible:
                result[item.severity.name] += 1
        return [result[item.name] for item in severities]

    @property
    def severity_distribution_dict(self) -> Dict[str, int]:
        """
        Get the distribution of vulnerabilities by severity.
        """
        result = {severity.name: 0 for severity in self.severities()}
        for item in self.vulnerabilities:
            if item.visible:
                result[item.severity.name] += 1
        return result
