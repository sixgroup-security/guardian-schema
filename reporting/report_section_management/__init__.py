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

from typing import Optional
from sqlmodel import SQLModel, Field

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class SectionStatistics(SQLModel):
    """
    Base class managing statistics for all reporting components.
    """
    # Percentage of completed children/plays
    percent_completed: Optional[float] = Field()
    # Statistics about vulnerabilities
    low_count: Optional[int] = Field()
    medium_count: Optional[int] = Field()
    high_count: Optional[int] = Field()
    critical_count: Optional[int] = Field()