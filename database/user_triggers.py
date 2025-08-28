from sqlalchemy.engine import Connection
from . import DatabaseFunction, DatabaseTrigger, TriggerEventEnum, TriggerWhenEnum, FunctionReturnEnum


class OnUserLockRevokeTokensTrigger(DatabaseFunction):
    """
    Creates a database trigger and function that revokes all JSON Web Tokens (JWTs)
    for a user when the user's account is locked (locked set to TRUE).
    """

    def __init__(self, connection: Connection):
        super().__init__(
            connection=connection,
            name="on_100_user_lock_revoke_tokens_trigger",
            returns=FunctionReturnEnum.trigger,
            triggers=[
                DatabaseTrigger(
                    name="on_user_lock_update",
                    table_name="\"user\"",
                    when=TriggerWhenEnum.after,
                    event=[TriggerEventEnum.update],
                    when_clause="OLD.locked IS DISTINCT FROM NEW.locked AND NEW.locked = TRUE"
                )
            ]
        )

    def _create(self) -> str:
        return """
BEGIN
    -- Revoke all tokens for the user when the account is locked
    IF NEW.locked = TRUE THEN
        UPDATE jsonwebtoken 
        SET revoked = TRUE 
        WHERE user_id = NEW.id;
    END IF;

    RETURN NEW;
END;
"""
