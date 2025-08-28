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


class OnBeforeApplicationUpdateInsertTrigger(DatabaseFunction):
    """
    Creates database triggers and function that ensure that column Application.next_pentest is correctly updated.
    """

    def __init__(self, connection: Connection):
        super().__init__(
            connection=connection,
            name="on_10_before_application_update_insert",
            returns=FunctionReturnEnum.trigger,
            triggers=[
                DatabaseTrigger(
                    name="on_10_before_application_insert",
                    table_name="application",
                    when=TriggerWhenEnum.before,
                    event=[TriggerEventEnum.insert],
                    when_clause="NEW.pentest_periodicity IS NOT NULL"
                ),
                DatabaseTrigger(
                    name="on_10_before_application_update",
                    table_name="application",
                    when=TriggerWhenEnum.before,
                    event=[TriggerEventEnum.update],
                    when_clause="OLD.last_pentest IS DISTINCT FROM NEW.last_pentest OR "
                                "OLD.pentest_periodicity IS DISTINCT FROM NEW.pentest_periodicity"
                )
            ])

    def _create(self) -> str:
        return """
    DECLARE
        last_day DATE;
        next_pentest DATE;
    BEGIN
        last_day := DATE_TRUNC('year', CURRENT_DATE) + INTERVAL '1 year - 1 day';

        -- If no pentest periodicity is defined
        IF NEW.pentest_periodicity IS NULL THEN
            NEW.next_pentest = NULL;
            RETURN NEW;
        END IF;

        -- RAISE NOTICE 'last_pt=%, last_sa=%, pt_periodicity=%, sa_periodicity=%, parameter=%, is_critical=%', NEW.last_pentest, NEW.pentest_periodicity, NEW.periodicity_parameter, is_critical;
        -- Compute the next_pentest date
        IF NEW.last_pentest IS NULL THEN
            next_pentest := last_day;
        ELSE
            next_pentest := NEW.last_pentest + (NEW.pentest_periodicity || ' months')::interval;
        END IF;

        NEW.next_pentest = next_pentest;
        RETURN NEW;
    END;
    """


class OnBeforeApplicationUpdateInsertCalculatePeriodicityTrigger(DatabaseFunction):
    """
    Keeps `Application.periodicity_parameter` and `pentest_periodicity` in sync with the record.
    Adds handling for the *decommissioned* state.
    """
    def __init__(self, connection: Connection):
        super().__init__(
            connection=connection,
            name="on_01_before_application_update_insert",
            returns=FunctionReturnEnum.trigger,
            triggers=[
                DatabaseTrigger(
                    name="on_01_before_application_periodicity_insert",
                    table_name="application",
                    when=TriggerWhenEnum.before,
                    event=[TriggerEventEnum.insert],
                    when_clause="NEW.state IS NOT NULL OR "
                                "NEW.in_scope IS NOT NULL OR "
                                "NEW.manual_pentest_periodicity IS NOT NULL"
                ),
                DatabaseTrigger(
                    name="on_01_before_application_periodicity_update",
                    table_name="application",
                    when=TriggerWhenEnum.before,
                    event=[TriggerEventEnum.update],
                    when_clause="OLD.state IS DISTINCT FROM NEW.state OR "
                                "OLD.in_scope IS DISTINCT FROM NEW.in_scope OR "
                                "OLD.manual_pentest_periodicity IS DISTINCT FROM NEW.manual_pentest_periodicity"
                )
            ])

    def _create(self) -> str:
        return """
    DECLARE
    BEGIN
        IF TG_OP = 'INSERT' OR TG_OP = 'UPDATE' THEN
            ----------------------------------------------------------------
            -- Case 0: Application is de-commissioned (state = 'decommissioned')
            ----------------------------------------------------------------
            IF NEW.state = 'decommissioned' THEN
                NEW.periodicity_parameter           := 'decommissioned';
                NEW.pentest_periodicity             := NULL;

            ----------------------------------------------------------------
            -- Case 1: Out of scope
            ----------------------------------------------------------------
            ELSIF NEW.in_scope = FALSE THEN
                NEW.periodicity_parameter           := 'out_of_scope';
                NEW.pentest_periodicity             := NULL;

            ----------------------------------------------------------------
            -- Case 2: Manual override
            ----------------------------------------------------------------
            ELSIF NEW.manual_pentest_periodicity IS NOT NULL THEN
                IF NEW.periodicity_details IS NULL THEN
                    RAISE EXCEPTION 'Manual periodicity requires a comment in periodicity_details';
                END IF;
                NEW.periodicity_parameter           := 'manual';
                NEW.pentest_periodicity             := NEW.manual_pentest_periodicity;

            ----------------------------------------------------------------
            -- Case 8: No match → clear
            ----------------------------------------------------------------
            ELSE
                NEW.periodicity_parameter           := NULL;
                NEW.pentest_periodicity             := NULL;
            END IF;
        END IF;
        RETURN NEW;
    END;
    """


class OnBeforeApplicationUpdateInsertCalculateOverdueStatusTrigger(DatabaseFunction):
    """
    Keeps `Application.overdue_status` in sync with the record.
    """
    def __init__(self, connection: Connection):
        super().__init__(
            connection=connection,
            name="on_20_before_application_update_insert",
            returns=FunctionReturnEnum.trigger,
            triggers=[
                DatabaseTrigger(
                    name="on_20_before_application_overdue_status_insert",
                    table_name="application",
                    when=TriggerWhenEnum.before,
                    event=[TriggerEventEnum.insert],
                    when_clause="NEW.periodicity_parameter IS NOT NULL OR "
                                "NEW.next_pentest IS NOT NULL OR "
                                "NEW.pentest_this_year IS NOT NULL"
                ),
                DatabaseTrigger(
                    name="on_20_before_application_overdue_status_update",
                    table_name="application",
                    when=TriggerWhenEnum.before,
                    event=[TriggerEventEnum.update],
                    when_clause="OLD.periodicity_parameter IS DISTINCT FROM NEW.periodicity_parameter OR "
                                "OLD.next_pentest IS DISTINCT FROM NEW.next_pentest OR "
                                "OLD.pentest_this_year IS DISTINCT FROM NEW.pentest_this_year"
                )
            ])

    def _create(self) -> str:
        return """
    DECLARE
        current_year INT;
        pentest_this_year BOOLEAN;
    BEGIN
        current_year := EXTRACT(YEAR FROM NOW());
        pentest_this_year := NEW.next_pentest IS NOT NULL AND EXTRACT(YEAR FROM NEW.next_pentest) <= current_year;

        IF pentest_this_year THEN
            IF COALESCE(NEW.pentest_this_year, 0) = 100 THEN
                NEW.overdue_status = 'no_overdue';
            ELSIF COALESCE(NEW.pentest_this_year, 0) = 50 THEN
                NEW.overdue_status = 'ongoing_project';
            ELSE
                NEW.overdue_status = 'no_project';
            END IF;
        ELSE
            NEW.overdue_status = 'no_overdue';
        END IF;
        RETURN NEW;
    END;
    """
