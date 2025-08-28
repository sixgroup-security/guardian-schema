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

import sys
import logging
from . import base_settings
from schema.user import User, UserReport

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class InjectingFilter(logging.Filter):
    """
    This is a custom logging filter that adds a username field to the log record.
    """
    def __init__(self, user: User | UserReport | None = None):
        super().__init__()
        self.user = user
        self.email = user.email if user else None
        self.client_ip = user.client_ip if user else None

    def filter(self, record):
        record.user_name = self.email or 'n/a'
        record.client_ip = self.client_ip or 'n/a'
        return True


def record_factory(*args, **kwargs):
    """
    This function is used to create a log record with the user name and client IP.
    """
    record = old_factory(*args, **kwargs)
    if not hasattr(record, 'user_name'):
        record.user_name = "n/a"
    if not hasattr(record, 'client_ip'):
        record.client_ip = "n/a"
    return record


# Define the handlers for the logger.
handlers = [logging.StreamHandler(sys.stdout)]
if base_settings.log_file:
    handlers.append(logging.FileHandler(base_settings.log_file))


# We set up a basic logger.
logging.basicConfig(
    format=base_settings.log_format,
    datefmt=base_settings.log_date_format,
    handlers=handlers,
    level=base_settings.log_level
)

old_factory = logging.getLogRecordFactory()
logging.setLogRecordFactory(record_factory)
