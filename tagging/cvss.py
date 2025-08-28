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
import logging
from uuid import UUID
from typing import List
from cvss import CVSS3, CVSS4
from datetime import datetime
from sqlalchemy.orm import Session
from sqlmodel import Field, SQLModel, Relationship
from sqlalchemy.sql import func
from schema.util import SeverityType, CVSS_VERSION_REGEX

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"

logger = logging.getLogger(__name__)


class CvssVersionEnum(enum.IntEnum):
    v3 = 3
    v4 = 4


class Cvss(SQLModel, table=True):
    """
    This class represents a CVSS vector.
    """
    id: UUID = Field(
        primary_key=True,
        index=True,
        sa_column_kwargs=dict(server_default=func.gen_random_uuid())
    )
    base_score: float = Field()
    # Base severity can be Null, if base score is 0.
    base_severity: SeverityType | None = Field()
    base_vector: str = Field(unique=True, regex=CVSS_VERSION_REGEX)
    # Internal information only
    created_at: datetime = Field(sa_column_kwargs=dict(server_default=func.now()))
    last_modified_at: datetime | None = Field(sa_column_kwargs=dict(onupdate=func.now()))
    # Relationship definitions
    vrt: List["Vrt"] = Relationship(back_populates="cvss")

    @staticmethod
    def calculate_base_score(vector: str) -> float:
        """
        Returns the CVSS base score.
        """
        vector_lower = vector.lower()
        if vector_lower.startswith("cvss:3"):
            return float(CVSS3(vector).base_score)
        elif vector_lower.startswith("cvss:4"):
            return float(CVSS4(vector).base_score)
        raise ValueError(f"Unknown CVSS version: {vector_lower}")

    @staticmethod
    def calculate_base_severity(value: float | str) -> SeverityType | None:
        """
        Returns the CVSS base severity.
        """
        result = value if isinstance(value, float) else Cvss.calculate_base_score(value)
        if result == 0:
            return None
        elif result < 4:
            return SeverityType.low
        elif result < 7:
            return SeverityType.medium
        elif result < 9:
            return SeverityType.high
        else:
            return SeverityType.critical

    @staticmethod
    def create_cvss3(vector: str | None):
        """
        Create a new CVSS object.
        """
        if not vector:
            return None
        result = vector if vector.lower().startswith("cvss:3") else f"CVSS:3.1/{vector}"
        base_score = Cvss.calculate_base_score(result)
        return Cvss(
            base_score=base_score,
            base_severity=Cvss.calculate_base_severity(base_score),
            base_vector=result
        )


def create_cvss_v3(
        session: Session,
        cvss_v3_vector: str | None
) -> Cvss | None:
    """
    Creates a CVSS v3 record based on the given data.
    """
    cvss = Cvss.create_cvss3(cvss_v3_vector)
    if not cvss:
        return None
    result = session.query(Cvss) \
        .filter_by(base_vector=cvss.base_vector) \
        .one_or_none()
    if result:
        result.base_severity = cvss.base_severity
        result.base_score = cvss.base_score
    else:
        result = cvss
        session.add(cvss)
        session.flush()
    return result
