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

from sqlalchemy.engine import Connection
from . import (DatabaseFunction, FunctionReturnEnum, FunctionArgument)

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


class UpdateApplicationDatesForApplicationIdFunction(DatabaseFunction):
    """
    Helper function that updates the last_pentest date as well as pentest_this_year for the given application ID.
    """

    def __init__(self, connection: Connection):
        super().__init__(
            connection=connection,
            name="update_application_dates_based_on_application_id",
            returns=FunctionReturnEnum.void,
            arguments=[
                FunctionArgument(name="app_id", argument_type="uuid")
            ]
        )

    def _create(self) -> str:
        return """
DECLARE
    l_last_pentest date;
    l_pentest_this_year int;
BEGIN
    -- Calculate values
    SELECT
        -- Calculate flags for this year (100: completed, 50: ongoing)
        MAX(
            CASE WHEN p.project_type = 'penetration_test' AND EXTRACT(YEAR FROM p.end_date) = EXTRACT(YEAR FROM CURRENT_DATE) THEN
                CASE WHEN p.state = 'completed' THEN 100
                WHEN p.state NOT IN ('backlog', 'cancelled', 'archived') THEN 50
                ELSE 0
                END
            ELSE 0
            END
        ) AS pentest_this_year,
        -- Calculate latest completion dates
        MAX(
            CASE WHEN p.project_type = 'penetration_test' AND p.state = 'completed' THEN p.completion_date END
        ) AS last_pentest
    INTO l_pentest_this_year, l_last_pentest
    FROM project p
    INNER JOIN applicationproject ap
        ON ap.project_id = p.id
        AND ap.application_id = app_id;

    -- Update values
    UPDATE application
        SET last_pentest = l_last_pentest,
            pentest_this_year = COALESCE(l_pentest_this_year, 0)
    WHERE id = app_id;
END;
"""


class UpdateApplicationDatesForProjectIdFunction(DatabaseFunction):
    """
    Helper function that updates the last_pentest date for the given project ID.
    """

    def __init__(self, connection: Connection):
        super().__init__(
            connection=connection,
            name="update_application_dates_based_on_project_id",
            returns=FunctionReturnEnum.void,
            arguments=[
                FunctionArgument(name="projectid", argument_type="uuid"),
            ]
        )

    def _create(self) -> str:
        return """
DECLARE
BEGIN
    UPDATE application a
    SET
        last_pentest = sub.last_pentest,
        pentest_this_year = COALESCE(sub.pentest_this_year, 0)
    FROM (
        SELECT
            ap.application_id,
            -- Calculate flags for this year (100: completed, 50: ongoing)
            MAX(
                CASE WHEN p.project_type = 'penetration_test' AND EXTRACT(YEAR FROM p.end_date) = EXTRACT(YEAR FROM CURRENT_DATE) THEN
                    CASE WHEN p.state = 'completed' THEN 100
                    WHEN p.state NOT IN ('backlog', 'cancelled', 'archived') THEN 50
                    ELSE 0
                    END
                ELSE 0
                END
            ) AS pentest_this_year,
            -- Calculate latest completion dates
            MAX(
                CASE WHEN p.project_type = 'penetration_test' AND p.state = 'completed' THEN p.completion_date END
            ) AS last_pentest
        FROM applicationproject ap
        JOIN project p ON p.id = ap.project_id
        WHERE p.project_type IN ('penetration_test')
            -- Only recalc for apps linked to the project that triggered this
            AND ap.application_id IN (
                SELECT application_id
                FROM applicationproject
                WHERE project_id = projectid
            )
        GROUP BY ap.application_id
    ) AS sub
    WHERE a.id = sub.application_id;
END;
"""


class ChooseValueDependingOnConditionFunction(DatabaseFunction):
    """
    Helper function that provides a simple, generic utility for conditional logic in SQL queries.
    """

    def __init__(self, connection: Connection):
        super().__init__(
            connection=connection,
            name="choose_value",
            returns=FunctionReturnEnum.anyelement,
            arguments=[
                FunctionArgument(name="condition", argument_type="boolean"),
                FunctionArgument(name="true_value", argument_type="anyelement"),
                FunctionArgument(name="false_value", argument_type="anyelement"),
            ]
        )

    def _create(self) -> str:
        return """
BEGIN
    IF condition THEN
        RETURN true_value;
    ELSE
        RETURN false_value;
    END IF;
END;
"""


class GetCvssSeverityValueFunction(DatabaseFunction):
    """
    Helper function that provides a simple, generic utility for conditional logic in SQL queries.
    """

    def __init__(self, connection: Connection):
        super().__init__(
            connection=connection,
            name="get_severity_value",
            returns=FunctionReturnEnum.int,
            arguments=[
                FunctionArgument(name="severity", argument_type="severitytype")
            ]
        )

    def _create(self) -> str:
        return """
BEGIN
    RETURN CASE
        WHEN severity IS NULL THEN NULL
        WHEN severity = 'info' THEN 0
        WHEN severity = 'low' THEN 10
        WHEN severity = 'medium' THEN 20
        WHEN severity = 'high' THEN 30
        WHEN severity = 'critical' THEN 40
        ELSE -1
    END;
END;
"""


class GetCvssSeverityStringFunction(DatabaseFunction):
    """
    Helper function that provides a simple, generic utility for conditional logic in SQL queries.
    """

    def __init__(self, connection: Connection):
        super().__init__(
            connection=connection,
            name="get_severity_string",
            returns=FunctionReturnEnum.text,
            arguments=[
                FunctionArgument(name="severity", argument_type="severitytype")
            ]
        )

    def _create(self) -> str:
        return """
BEGIN
    RETURN CASE
        WHEN severity IS NULL THEN NULL
        WHEN severity = 'info' THEN 'Info'
        WHEN severity = 'low' THEN 'Low'
        WHEN severity = 'medium' THEN 'Medium'
        WHEN severity = 'high' THEN 'High'
        WHEN severity = 'critical' THEN 'Critical'
        ELSE 'Undefined (bug)'
    END;
END;
"""


class GetSyncStateValueFunction(DatabaseFunction):
    """
    Helper function that provides a simple, generic utility for conditional logic in SQL queries.
    """

    def __init__(self, connection: Connection):
        super().__init__(
            connection=connection,
            name="get_sync_state_value",
            returns=FunctionReturnEnum.int,
            arguments=[
                FunctionArgument(name="sync_state", argument_type="applicationsyncstate")
            ]
        )

    def _create(self) -> str:
        return """
BEGIN
    RETURN CASE
        WHEN sync_state IS NULL THEN NULL
        WHEN sync_state = 'successful' THEN 0
        WHEN sync_state = 'not_synched' THEN 10
        WHEN sync_state = 'failed' THEN 20
        ELSE -1
    END;
END;
"""


class GetSyncStateStringFunction(DatabaseFunction):
    """
    Helper function that provides a simple, generic utility for conditional logic in SQL queries.
    """

    def __init__(self, connection: Connection):
        super().__init__(
            connection=connection,
            name="get_sync_state_string",
            returns=FunctionReturnEnum.text,
            arguments=[
                FunctionArgument(name="sync_state", argument_type="applicationsyncstate")
            ]
        )

    def _create(self) -> str:
        return """
BEGIN
    RETURN CASE
        WHEN sync_state IS NULL THEN NULL
        WHEN sync_state = 'successful' THEN 'Successful'
        WHEN sync_state = 'not_synched' THEN 'Not Synched'
        WHEN sync_state = 'failed' THEN 'Failed'
        ELSE 'Undefined (bug)'
    END;
END;
"""


class GetApplicationOverdueValueFunction(DatabaseFunction):
    """
    Helper function that provides a simple, generic utility for conditional logic in SQL queries.
    """

    def __init__(self, connection: Connection):
        super().__init__(
            connection=connection,
            name="get_application_overdue_value",
            returns=FunctionReturnEnum.int,
            arguments=[
                # Application row
                FunctionArgument(name="a", argument_type="application")
            ]
        )

    def _create(self) -> str:
        return """
BEGIN
    RETURN CASE
        WHEN a.overdue_status IS NULL THEN 10
        WHEN a.overdue_status = 'no_overdue' THEN 10
        WHEN a.overdue_status = 'ongoing_project' THEN 20
        WHEN a.overdue_status = 'no_project' THEN 30
        ELSE -1
    END;
END;
"""


class GetApplicationOverdueStringFunction(DatabaseFunction):
    """
    Helper function that provides a simple, generic utility for conditional logic in SQL queries.
    """

    def __init__(self, connection: Connection):
        super().__init__(
            connection=connection,
            name="get_application_overdue_string",
            returns=FunctionReturnEnum.text,
            arguments=[
                # Application row
                FunctionArgument(name="a", argument_type="application")
            ]
        )

    def _create(self) -> str:
        return """
DECLARE
    overdue INT;
BEGIN
    -- Call get_application_overdue_value and store the result in sync_state
    overdue := get_application_overdue_value(a);

    -- Return the corresponding label based on sync_state
    RETURN CASE
        WHEN overdue = 10 THEN 'No Overdue'
        WHEN overdue = 20 THEN 'Ongoing Project'
        WHEN overdue = 30 THEN 'No Project'
        ELSE 'Undefined (bug)'
    END;
END;
"""



class GetProjectIdFunction(DatabaseFunction):
    """
    Helper function that provides a simple, generic utility for conditional logic in SQL queries.
    """

    def __init__(self, connection: Connection):
        super().__init__(
            connection=connection,
            name="get_project_id",
            returns=FunctionReturnEnum.text,
            arguments=[
                # Project row
                FunctionArgument(name="p", argument_type="project"),
            ]
        )

    def _create(self) -> str:
        return """
BEGIN
    RETURN CONCAT(CASE
        WHEN p.project_type IS NULL THEN ''
        WHEN p.project_type = 'penetration_test' THEN 'CCPT'
        WHEN p.project_type = 'security_assessment' THEN 'CCSA'
        WHEN p.project_type = 'bug_bounty' THEN 'CCBB'
        WHEN p.project_type = 'attack_modelling' THEN 'CCTM'
        WHEN p.project_type = 'red_team_exercise' THEN 'CCRT'
        WHEN p.project_type = 'purple_team_exercise' THEN 'CCPE'
    END, '-', p.year, '-', LPAD(p.increment::text, 3, '0'));
END;
"""
