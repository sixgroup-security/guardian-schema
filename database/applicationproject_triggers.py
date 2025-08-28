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

from sqlalchemy.engine import Connection
from . import DatabaseFunction, DatabaseTrigger, TriggerEventEnum, TriggerWhenEnum, FunctionReturnEnum

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class OnAfterApplicationProjectUpdateInsertDeleteTrigger(DatabaseFunction):
    """
    Creates database triggers and function that ensure that column application.last_pentest is
    correctly updated based on table project.
    """
    def __init__(self, connection: Connection):
        super().__init__(
            connection=connection,
            name="on_03_after_applicationproject_change_trigger",
            returns=FunctionReturnEnum.trigger,
            triggers=[
                DatabaseTrigger(
                    name="on_after_applicationproject_change_delete",
                    table_name="applicationproject",
                    when=TriggerWhenEnum.after,
                    event=[TriggerEventEnum.delete]
                ),
                DatabaseTrigger(
                    name="on_after_applicationproject_change_insert",
                    table_name="applicationproject",
                    when=TriggerWhenEnum.after,
                    event=[TriggerEventEnum.insert]
                ),
                DatabaseTrigger(
                    name="on_after_applicationproject_change_update",
                    table_name="applicationproject",
                    when=TriggerWhenEnum.after,
                    when_clause="OLD.project_id IS DISTINCT FROM NEW.project_id OR "
                                "OLD.application_id IS DISTINCT FROM NEW.application_id",
                    event=[TriggerEventEnum.update]
                ),
            ])

    def _create(self) -> str:
        return """
    DECLARE
        project_type projecttype;
        application_id uuid;
    BEGIN
        IF TG_OP = 'DELETE' THEN
            project_type := (SELECT p.project_type
                                    FROM project p
                                    WHERE p.id = OLD.project_id);
            application_id = OLD.application_id;
        ELSIF TG_OP = 'INSERT' THEN
            project_type := (SELECT p.project_type
                                    FROM project p
                                    WHERE p.id = NEW.project_id);
            application_id = NEW.application_id;
        ELSE
            RAISE EXCEPTION 'Did not expect update operation on records in table update_application_dates.';
        END IF;

        IF project_type = 'penetration_test' THEN
            PERFORM update_application_dates_based_on_application_id(application_id);
        END IF;
        RETURN NULL;
    END;
    """
