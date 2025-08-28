from sqlalchemy import text
from sqlalchemy.engine import Connection


class DatabaseViewBase:
    """
    Base class to manage database views
    """
    def __init__(self, connection: Connection, name: str, content: str):
        self._connection = connection
        self.name = name.strip()
        self.content = content.strip()

    def _execute(self, content: str):
        """
        Executes the given SQL statement.
        """
        # print(content)
        self._connection.execute(text(content).execution_options(autocommit=True))

    def drop(self):
        """
        Drop the view.
        """
        self._execute("DROP VIEW IF EXISTS " + self.name + " CASCADE;")

    def create(self):
        """
        Create the function together with all calling triggers.
        """
        self._execute(f"""CREATE OR REPLACE VIEW {self.name} AS
{self.content}""")
