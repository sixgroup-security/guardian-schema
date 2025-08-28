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


class OnBeforeProjectUpdateInsertTrigger(DatabaseFunction):
    """
    Creates database triggers and function that ensure that column Project.completion_date is:
    - set to NULL, if the project status is not completed.
    - set to the date when the project status was set to completed.
    """
    def __init__(self, connection: Connection):
        super().__init__(
            connection=connection,
            name="on_01_before_project_update_insert",
            returns=FunctionReturnEnum.trigger,
            triggers=[
                DatabaseTrigger(
                    name="on_before_project_update",
                    table_name="project",
                    when=TriggerWhenEnum.before,
                    event=[TriggerEventEnum.update],
                    when_clause="OLD.state IS DISTINCT FROM NEW.state"
                ),
                DatabaseTrigger(
                    name="on_before_project_insert",
                    table_name="project",
                    when=TriggerWhenEnum.before,
                    event=[TriggerEventEnum.insert],
                    when_clause="(NEW.completion_date IS NOT NULL AND NEW.state <> 'completed') OR "
                                "(NEW.completion_date IS NULL AND NEW.state = 'completed')"
                )
            ]
        )

    def _create(self) -> str:
        return """
DECLARE
BEGIN
    -- RAISE NOTICE 'BEGIN FUNCTION: on_01_before_project_update_insert';
    IF TG_OP = 'UPDATE' AND OLD.state IS DISTINCT FROM NEW.state THEN
        -- If the project's state changed, then we have to accordingly update column completion_date. 
        IF NEW.state = 'completed' THEN
            NEW.completion_date = COALESCE(NEW.completion_date, NOW());
        ELSE
            NEW.completion_date = NULL;
        END IF;
    ELSIF TG_OP = 'INSERT' THEN
        IF NEW.completion_date IS NOT NULL AND NEW.state <> 'completed' THEN
            -- If a new project is created and its completion_date is set but the status is not completed.
            NEW.completion_date = NULL;
        ELSIF NEW.completion_date IS NULL AND NEW.state = 'completed' THEN
            -- If a new project is created and its completion_date is not set but the its status is set to completed.
            NEW.completion_date = NOW();
        END IF;
    ELSIF TG_OP = 'DELETE' THEN
        PERFORM update_application_dates_based_on_project_id(OLD.id);
    END IF;
    -- RAISE NOTICE 'END FUNCTION: on_01_before_project_update_insert';
    RETURN NEW;
END;"""


class OnAfterProjectUpdateTrigger(DatabaseFunction):
    """
    Creates database triggers and function that ensure that column application.last_pentest is correctly updated
    based on table project.
    """
    def __init__(self, connection: Connection):
        super().__init__(
            connection=connection,
            name="on_02_after_project_update",
            returns=FunctionReturnEnum.trigger,
            triggers=[
                DatabaseTrigger(
                    name="on_after_project_insert",
                    table_name="project",
                    when=TriggerWhenEnum.after,
                    event=[TriggerEventEnum.insert],
                    when_clause="NEW.completion_date IS NOT NULL AND NEW.project_type IN ('penetration_test')"
                ),
                DatabaseTrigger(
                    name="on_after_project_update",
                    table_name="project",
                    when=TriggerWhenEnum.after,
                    event=[TriggerEventEnum.update],
                    when_clause="NEW.project_type IS DISTINCT FROM OLD.project_type OR "
                                "NEW.state IS DISTINCT FROM OLD.state OR "
                                "NEW.completion_date IS DISTINCT FROM OLD.completion_date"
                ),
            ]
        )

    def _create(self) -> str:
        return """
DECLARE
    max_completion_date date;
BEGIN
    -- RAISE NOTICE 'BEGIN FUNCTION: on_02_after_project_update';
    IF TG_OP = 'INSERT' AND NEW.completion_date IS NOT NULL THEN
        PERFORM update_application_dates_based_on_project_id(NEW.id);
    ELSIF TG_OP = 'UPDATE' THEN
        IF NEW.project_type IS DISTINCT FROM OLD.project_type THEN
            -- If the project type changed and is/was a penetration test, then we need to update the statistics for
            -- penetration test for all associated applications.
            IF OLD.project_type = 'penetration_test' THEN
                PERFORM update_application_dates_based_on_project_id(OLD.id);
            END IF;
            IF NEW.project_type = 'penetration_test' THEN
                PERFORM update_application_dates_based_on_project_id(NEW.id);
            END IF;
        END IF;
        IF NEW.state IS DISTINCT FROM OLD.state OR NEW.completion_date IS DISTINCT FROM OLD.completion_date THEN
            -- Only the state and completion date changed and the project type remained the same. In this case, we only
            -- have to re-calculate the state.
            PERFORM update_application_dates_based_on_project_id(NEW.id); 
        END IF;
    END IF;
    -- RAISE NOTICE 'END FUNCTION: on_02_after_project_update';
    RETURN NULL;
END;
"""


class OnBeforeProjectUpdateInsertTrigger2(DatabaseFunction):
    """
    Creates database triggers and function that ensure that column Project.increment is correctly computed/updated.
    """
    def __init__(self, connection: Connection):
        super().__init__(
            connection=connection,
            name="on_04_before_project_increment_update_insert",
            returns=FunctionReturnEnum.trigger,
            triggers=[
                DatabaseTrigger(
                    name="on_before_project_increment_update",
                    table_name="project",
                    when=TriggerWhenEnum.before,
                    event=[TriggerEventEnum.update],
                    when_clause="OLD.project_type IS DISTINCT FROM NEW.project_type OR "
                                "OLD.year IS DISTINCT FROM NEW.year OR "
                                "EXTRACT(YEAR FROM OLD.start_date) IS DISTINCT FROM EXTRACT(YEAR FROM NEW.start_date)"
                ),
                DatabaseTrigger(
                    name="on_before_project_increment_insert",
                    table_name="project",
                    when=TriggerWhenEnum.before,
                    event=[TriggerEventEnum.insert]
                )
            ]
        )

    def _create(self) -> str:
        return """
DECLARE
BEGIN
    -- RAISE NOTICE 'BEGIN FUNCTION: on_01_before_project_increment_update_insert';
    IF TG_OP = 'INSERT' THEN
        IF NEW.year IS NULL THEN
            NEW.year := EXTRACT(YEAR FROM NEW.start_date);
        END IF;
        IF NEW.increment IS NULL THEN
            NEW.increment := (SELECT COALESCE(MAX(increment), 0) + 1
                                  FROM project
                                  WHERE year = NEW.year AND project_type = NEW.project_type);
        END IF;
    ELSIF TG_OP = 'UPDATE' AND (OLD.project_type IS DISTINCT FROM NEW.project_type OR
                                OLD.year IS DISTINCT FROM NEW.year OR
                                OLD.start_date IS DISTINCT FROM NEW.start_date) THEN
        NEW.year := EXTRACT(YEAR FROM NEW.start_date);
        NEW.increment := (SELECT COALESCE(MAX(increment), 0) + 1
                              FROM project
                              WHERE year = NEW.year AND project_type = NEW.project_type);
    END IF;
    RETURN NEW;
END;
"""


class OnAfterProjectUpdateInsertDeleteTrigger(DatabaseFunction):
    """
    Creates database triggers and function that ensure that column Application.last_penetration_test is correctly
    computed/updated.

    In addition, it performs a report version cleanup, once the project is set to completed.
    """
    def __init__(self, connection: Connection):
        super().__init__(
            connection=connection,
            name="on_05_after_project_change_trigger",
            returns=FunctionReturnEnum.trigger,
            triggers=[
                DatabaseTrigger(
                    name="on_after_project_delete",
                    table_name="project",
                    when=TriggerWhenEnum.after,
                    event=[TriggerEventEnum.delete]
                ),
                DatabaseTrigger(
                    name="on_after_project_insert",
                    table_name="project",
                    when=TriggerWhenEnum.after,
                    event=[TriggerEventEnum.insert]
                ),
                DatabaseTrigger(
                    name="on_after_project_update_on_state_change",
                    table_name="project",
                    when=TriggerWhenEnum.after,
                    event=[TriggerEventEnum.update],
                    when_clause="OLD.state IS DISTINCT FROM NEW.state"
                )
            ]
        )

    def _create(self) -> str:
        return """
DECLARE
BEGIN
    -- RAISE NOTICE 'BEGIN FUNCTION: on_01_before_project_increment_update_insert';
    IF TG_OP = 'DELETE' AND OLD.project_type = 'penetration_test' THEN
        PERFORM update_application_dates_based_on_project_id(OLD.id);
    ELSIF TG_OP = 'INSERT' AND NEW.project_type = 'penetration_test' THEN
        PERFORM update_application_dates_based_on_project_id(NEW.id);
    ELSIF TG_OP = 'UPDATE' AND OLD.state IS DISTINCT FROM NEW.state THEN
        PERFORM update_application_dates_based_on_project_id(NEW.id);

        -- We perform a report version cleanup once the project is completed
        IF NEW.state = 'completed' AND EXISTS (
            SELECT 1 FROM reportversion rv
            INNER JOIN report r ON r.id = rv.report_id
            WHERE r.project_id = NEW.id AND rv.status = 'draft'
        ) THEN
            UPDATE reportversion rv
            SET pdf = NULL,
                pdf_log = NULL,
                tex = NULL,
                xlsx = NULL
            FROM report r
            WHERE r.id = rv.report_id
              AND r.project_id = NEW.id
              AND rv.status = 'draft';
        END IF;
        -- on_02_after_project_update updates Application.last_penetration_test and Application.last_penetration_test
    END IF;
    RETURN NULL;
END;
"""
