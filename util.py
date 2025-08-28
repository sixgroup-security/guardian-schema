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

import uuid
import enum
import hashlib
from types import FrameType
from typing import Dict, Callable, Set, List
from sqlmodel import SQLModel
from sqlalchemy import UniqueConstraint
from sqlalchemy.orm import Session
from sqlalchemy.ext.compiler import compiles
from typing import Any, Type
from fastapi import status
from pydantic import ConfigDict, Field as PydanticField, BaseModel, AliasChoices, field_validator, computed_field
from schema.reporting.report_language import ReportLanguage

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


CVSS_VERSION_REGEX = r"CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH](?:/E:[UFPH])?(?:/RL:[OTWU])?(?:/RC:[URC])?(?:/CR:[LMH])?(?:/IR:[LMH])?(?:/AR:[LMH])?(?:/MAV:[NALP])?(?:/MAC:[LH])?(?:/MPR:[NLH])?(?:/MUI:[NR])?(?:/MS:[UC])?(?:/MC:[NLH])?(?:/MI:[NLH])?(?:/MA:[NLH])?"


# This is a workaround to add the NULLS NOT DISTINCT option to the UNIQUE constraint.
# Source: https://stackoverflow.com/questions/57646553/treating-null-as-a-distinct-value-in-a-table-unique-constraint
UniqueConstraint.argument_for("postgresql", 'nulls_not_distinct', None)


@compiles(UniqueConstraint, "postgresql")
def compile_create_uc(create, compiler, **kw):
    """Add NULLS NOT DISTINCT if its in args."""
    stmt = compiler.visit_unique_constraint(create, **kw)
    postgresql_opts = create.dialect_options["postgresql"]

    if postgresql_opts.get("nulls_not_distinct"):
        return stmt.rstrip().replace("UNIQUE (", "UNIQUE NULLS NOT DISTINCT (")
    return stmt


class SeverityType(enum.IntEnum):
    """
    Defines the severity of a vulnerability.
    """
    info = 0
    low = 10
    medium = 20
    high = 30
    critical = 40


class ProjectType(enum.IntEnum):
    attack_modelling = 10
    bug_bounty = 20
    red_team_exercise = 30
    penetration_test = 40
    purple_team_exercise = 50
    security_assessment = 60


class ProjectTypePrefix(enum.Enum):
    attack_modelling = "CCTM"
    bug_bounty = "CCBB"
    red_team_exercise = "CCRT"
    penetration_test = "CCPT"
    purple_team_exercise = "CCPE"
    security_assessment = "CCSA"


class GuardianRoleEnum(enum.IntEnum):
    admin = 100
    auditor = 200
    manager = 300
    leadpentester = 400
    pentester = 500
    customer = 600
    api = 900


class ApiPermissionDetails:
    def __init__(self, description: str, api_access: bool = False):
        self.description = description
        self.api_access = api_access


class ApiPermissionEnum(enum.Enum):
    """
    Enum that specifies all atomic REST API permissions.

    Based on this enum, the permissions for all Guardian user roles can be defined.
    """
    access_token_read = ApiPermissionDetails(
        description="Read access token"
    )
    access_token_delete = ApiPermissionDetails(
        description="Delete an access token"
    )
    access_token_create = ApiPermissionDetails(
        description="Create an access token"
    )
    access_token_update = ApiPermissionDetails(
        description="Update an access token"
    )
    application_read = ApiPermissionDetails(
        description="Read applications",
        api_access=True
    )
    application_delete = ApiPermissionDetails(
        description="Delete an application"
    )
    application_create = ApiPermissionDetails(
        description="Create an application"
    )
    application_update = ApiPermissionDetails(
        description="Update an application",
        api_access=True
    )
    application_project_read = ApiPermissionDetails(
        description="Read an application's projects",
        api_access=True
    )
    application_project_batch_create = ApiPermissionDetails(
        description="Batch create projects for a given list of applications",
        api_access=True
    )
    application_tag_read = ApiPermissionDetails(
        description="Read an application's tags",
        api_access=True
    )
    application_tag_create = ApiPermissionDetails(
        description="Create new application tags"
    )
    application_periodicity_criteria_update = ApiPermissionDetails(
        description="Update the applications' periodicity criteria"
    )
    calendar_read = ApiPermissionDetails(
        description="Read the calendar"
    )
    country_read = ApiPermissionDetails(
        description="Read countries",
        api_access=True
    )
    customer_read = ApiPermissionDetails(
        description="Read customers",
        api_access=True
    )
    customer_delete = ApiPermissionDetails(
        description="Delete a customer"
    )
    customer_create = ApiPermissionDetails(
        description="Create a customer",
        api_access=True
    )
    customer_update = ApiPermissionDetails(
        description="Update a customer",
        api_access=True
    )
    dashboard_read = ApiPermissionDetails(
        description="Read the dashboard"
    )
    measure_read = ApiPermissionDetails(
        description="Read measures",
        api_access=True
    )
    measure_delete = ApiPermissionDetails(
        description="Delete a measure",
        api_access=True
    )
    measure_create = ApiPermissionDetails(
        description="Create a measure",
        api_access=True
    )
    measure_update = ApiPermissionDetails(
        description="Update a measure",
        api_access=True
    )
    measure_tag_read = ApiPermissionDetails(
        description="Read measure tags",
        api_access=True
    )
    measure_tag_create = ApiPermissionDetails(
        description="Create new measure tags",
        api_access=True
    )
    pentest_playbook_read = ApiPermissionDetails(
        description="Read pentest playbooks",
        api_access=True
    )
    pentest_playbook_delete = ApiPermissionDetails(
        description="Delete a pentest playbook",
        api_access=True
    )
    pentest_playbook_create = ApiPermissionDetails(
        description="Create a pentest playbook",
        api_access=True
    )
    pentest_playbook_update = ApiPermissionDetails(
        description="Update a pentest playbook",
        api_access=True
    )
    pentest_report_read = ApiPermissionDetails(
        description="Read pentest reports",
        api_access=True
    )
    pentest_report_read_latest_final_pdf = ApiPermissionDetails(
        description="Read latest final pentest PDF report",
        api_access=True
    )
    pentest_report_read_latest_final_xlsx = ApiPermissionDetails(
        description="Read latest final pentest XLSX report",
        api_access=True
    )
    pentest_report_delete = ApiPermissionDetails(
        description="Delete a pentest report",
        api_access=True
    )
    pentest_report_create = ApiPermissionDetails(
        description="Create a pentest report",
        api_access=True
    )
    pentest_report_update = ApiPermissionDetails(
        description="Update a pentest report",
        api_access=True
    )
    playbook_read = ApiPermissionDetails(
        description="Read playbooks",
        api_access=True
    )
    playbook_delete = ApiPermissionDetails(
        description="Delete a playbook",
        api_access=True
    )
    playbook_create = ApiPermissionDetails(
        description="Create a playbook",
        api_access=True
    )
    playbook_update = ApiPermissionDetails(
        description="Update a playbook",
        api_access=True
    )
    project_access_read = ApiPermissionDetails(
        description="Read project access permissions",
        api_access=True
    )
    project_access_delete = ApiPermissionDetails(
        description="Delete a project access permission",
        api_access=True
    )
    project_access_create = ApiPermissionDetails(
        description="Create a project access permission",
        api_access=True
    )
    project_access_update = ApiPermissionDetails(
        description="Update a project access permission",
        api_access=True
    )
    project_read = ApiPermissionDetails(
        description="Read projects",
        api_access=True
    )
    project_delete = ApiPermissionDetails(
        description="Delete a project",
        api_access=True
    )
    project_create = ApiPermissionDetails(
        description="Create a project",
        api_access=True
    )
    project_update = ApiPermissionDetails(
        description="Update a project",
        api_access=True
    )
    project_comment_delete = ApiPermissionDetails(
        description="Delete a project comment",
        api_access=True
    )
    project_tag_read = ApiPermissionDetails(
        description="Read project tags",
        api_access=True
    )
    project_tag_create = ApiPermissionDetails(
        description="Create new project tags",
        api_access=True
    )
    provider_read = ApiPermissionDetails(
        description="Read providers",
        api_access=True
    )
    provider_delete = ApiPermissionDetails(
        description="Delete a provider",
        api_access=True
    )
    provider_create = ApiPermissionDetails(
        description="Create a provider",
        api_access=True
    )
    provider_update = ApiPermissionDetails(
        description="Update a provider",
        api_access=True
    )
    report_language_read = ApiPermissionDetails(
        description="Read report languages"
    )
    report_language_delete = ApiPermissionDetails(
        description="Delete a report language"
    )
    report_language_create = ApiPermissionDetails(
        description="Create a report language"
    )
    report_language_update = ApiPermissionDetails(
        description="Update a report language"
    )
    report_template_read = ApiPermissionDetails(
        description="Read report templates",
        api_access=True
    )
    report_template_delete = ApiPermissionDetails(
        description="Delete a report template",
        api_access=True
    )
    report_template_create = ApiPermissionDetails(
        description="Create a report template",
        api_access=True
    )
    report_template_update = ApiPermissionDetails(
        description="Update a report template",
        api_access=True
    )
    test_procedure_read = ApiPermissionDetails(
        description="Read test procedures",
        api_access=True
    )
    test_procedure_delete = ApiPermissionDetails(
        description="Delete a test procedure",
        api_access=True
    )
    test_procedure_create = ApiPermissionDetails(
        description="Create a test procedure",
        api_access=True
    )
    test_procedure_update = ApiPermissionDetails(
        description="Update a test procedure",
        api_access=True
    )
    test_procedure_tag_read = ApiPermissionDetails(
        description="Read test procedure tags",
        api_access=True
    )
    test_procedure_tag_create = ApiPermissionDetails(
        description="Create new test procedure tags",
        api_access=True
    )
    user_read = ApiPermissionDetails(
        description="Read users",
        api_access=True
    )
    user_delete = ApiPermissionDetails(
        description="Delete a user"
    )
    user_create = ApiPermissionDetails(
        description="Create a user"
    )
    user_update = ApiPermissionDetails(
        description="Update a user"
    )
    user_me_read = ApiPermissionDetails(
        description="Read the current user"
    )
    user_me_update = ApiPermissionDetails(
        description="Update the current user"
    )
    user_me_report_language_update = ApiPermissionDetails(
        description="Update the current user's preferred report language",
        api_access=True
    )
    vulnerability_classifications_read = ApiPermissionDetails(
        description="Read vulnerability classifications",
        api_access=True
    )
    vulnerability_template_read = ApiPermissionDetails(
        description="Read vulnerability templates",
        api_access=True
    )
    vulnerability_template_delete = ApiPermissionDetails(
        description="Delete a vulnerability template",
        api_access=True
    )
    vulnerability_template_create = ApiPermissionDetails(
        description="Create a vulnerability template",
        api_access=True
    )
    vulnerability_template_update = ApiPermissionDetails(
        description="Update a vulnerability template",
        api_access=True
    )
    vulnerability_template_tag_read = ApiPermissionDetails(
        description="Read vulnerability template tags",
        api_access=True
    )
    vulnerability_template_tag_create = ApiPermissionDetails(
        description="Create new vulnerability template tags",
        api_access=True
    )
    websocket = ApiPermissionDetails(
        description="Establish a websocket connection"
    )


# Perform a check to ensure that there are no duplicate values in the enum.
scopes = [item for item in ApiPermissionEnum]
assert len(scopes) == 84
result_count = {}
for scope in scopes:
    if scope.value not in result_count:
        result_count[scope.value] = 0
    else:
        raise ValueError(f"Duplicate value '{scope.value}' in enum '{scope.name}'.")


class StatusEnum(enum.IntEnum):
    error = enum.auto()
    success = enum.auto()
    info = enum.auto()
    warning = enum.auto()


class StatusMessage(BaseModel):
    """
    Status message that is used to send status information to the frontend.
    """
    model_config = ConfigDict(
        from_attributes=True,
        use_enum_values=False,  # Ensure that enum values are not automatically used
        json_encoders={StatusEnum: lambda x: x.name}
    )
    status: int
    severity: StatusEnum
    message: str
    open: bool = PydanticField(default=True)
    error_code: uuid.UUID | None = PydanticField(default=None)
    payload: Dict[str, Any] | None = PydanticField(default=None)

    @field_validator('severity', mode='before')
    def convert_int_serial(cls, v):
        if isinstance(v, str):
            v = StatusEnum[v]
        return v



class GuardianError(Exception):
    """
    Base class for all Guardian exceptions.
    """
    def __init__(
            self,
            message: str | None = None,
            account: Any | None = None,
            exc: Exception | None = None
    ):
        super().__init__(message)
        self.account = account
        self.exc = exc


class AuthenticationError(GuardianError):
    """
    Raised when account authentication/authorization failed.
    """

    def __init__(
            self,
            message: str = "User is not authenticated.",
            account: Any | None = None,
            exc: Exception | None = None
    ):
        super().__init__(
            message=message,
            account=account,
            exc=exc
        )


class NotFoundError(GuardianError):
    def __init__(
            self,
            message: str,
            account: Any | None = None,
            exc: Exception | None = None
    ):
        super().__init__(
            message=message,
            account=account,
            exc=exc
        )


class InvalidDataError(GuardianError):
    def __init__(
            self,
            message: str,
            account: Any | None = None,
            exc: Exception | None = None
    ):
        super().__init__(
            message=message,
            account=account,
            exc=exc
        )


class InternalServerError(GuardianError):
    def __init__(self, exception: Exception):
        self.parent_exception = exception
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected internal server error occurred."
        )


class AuthorizationError(GuardianError):
    """
    Raised when account authorization failed.
    """

    def __init__(
            self,
            message: str = "Authorization failed.",
            account: Any | None = None,
            exc: Exception | None = None
    ):
        super().__init__(
            message=message,
            account=account,
            exc=exc
        )


class EntityLookup(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str


class ReportSectionLookup(SQLModel):
    id: uuid.UUID
    name: str


class ProjectLookup(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str = PydanticField(exclude=True)
    project_id: str

    @computed_field
    def label(self) -> str:
        return f"{self.project_id} - {self.name}"


class UserLookup(BaseModel):
    id: uuid.UUID
    full_name: str = PydanticField(
        serialization_alias="label",
        validation_alias=AliasChoices("label", "full_name")
    )


# Dictionary that maps a user roles to REST API permissions/scopes.
ROLE_PERMISSION_MAPPING = {
    GuardianRoleEnum.admin.name: [item.name for item in ApiPermissionEnum],
    GuardianRoleEnum.auditor.name: [
        ApiPermissionEnum.application_read.name,
        ApiPermissionEnum.application_project_read.name,
        ApiPermissionEnum.calendar_read.name,
        ApiPermissionEnum.country_read.name,
        ApiPermissionEnum.customer_read.name,
        ApiPermissionEnum.dashboard_read.name,
        ApiPermissionEnum.pentest_report_read_latest_final_pdf.name,
        ApiPermissionEnum.pentest_report_read_latest_final_xlsx.name,
        ApiPermissionEnum.project_access_read.name,
        ApiPermissionEnum.project_read.name,
        ApiPermissionEnum.provider_read.name,
        ApiPermissionEnum.user_read.name,
        ApiPermissionEnum.user_me_read.name,
        ApiPermissionEnum.user_me_update.name,
    ],
    GuardianRoleEnum.manager.name: [
        ApiPermissionEnum.application_read.name,
        # ApiPermissionEnum.application_delete.name,
        # ApiPermissionEnum.application_create.name,
        # ApiPermissionEnum.application_update.name,
        ApiPermissionEnum.application_project_read.name,
        # ApiPermissionEnum.application_tag_read.name,
        # ApiPermissionEnum.application_tag_create.name,
        ApiPermissionEnum.calendar_read.name,
        ApiPermissionEnum.country_read.name,
        ApiPermissionEnum.customer_read.name,
        ApiPermissionEnum.dashboard_read.name,
        ApiPermissionEnum.pentest_report_read_latest_final_pdf.name,
        ApiPermissionEnum.pentest_report_read_latest_final_xlsx.name,
        ApiPermissionEnum.project_access_read.name,
        ApiPermissionEnum.project_access_delete.name,
        ApiPermissionEnum.project_access_create.name,
        ApiPermissionEnum.project_access_update.name,
        ApiPermissionEnum.project_read.name,
        # ApiPermissionEnum.project_delete.name,
        ApiPermissionEnum.project_create.name,
        ApiPermissionEnum.project_update.name,
        ApiPermissionEnum.project_tag_read.name,
        ApiPermissionEnum.project_tag_create.name,
        ApiPermissionEnum.provider_read.name,
        ApiPermissionEnum.user_read.name,
        ApiPermissionEnum.user_read.name,
        ApiPermissionEnum.user_me_read.name,
        ApiPermissionEnum.user_me_update.name,
    ],
    GuardianRoleEnum.leadpentester.name: [
        # TODO: Define permissions for the leadpentester role
    ],
    GuardianRoleEnum.pentester.name: [
        # TODO: Define permissions for the pentester role
    ],
    GuardianRoleEnum.customer.name: [
        ApiPermissionEnum.application_read.name,
        ApiPermissionEnum.application_project_read.name,
        ApiPermissionEnum.country_read.name,
        ApiPermissionEnum.customer_read.name,
        # ApiPermissionEnum.pentest_report_read.name,
        ApiPermissionEnum.project_read.name,
        ApiPermissionEnum.provider_read.name,
        ApiPermissionEnum.user_me_read.name,
        ApiPermissionEnum.user_me_update.name,
    ],
    GuardianRoleEnum.api.name: [
        ApiPermissionEnum.access_token_create.name,
        ApiPermissionEnum.access_token_delete.name,
        ApiPermissionEnum.access_token_read.name,
        ApiPermissionEnum.access_token_update.name
    ],
}


# We create a lookup table for all roles and their API key permissions
ROLE_API_PERMISSIONS = {}
for role, permissions in ROLE_PERMISSION_MAPPING.items():
    ROLE_API_PERMISSIONS[role] = []
    for access in permissions:
        info = ApiPermissionEnum[access]
        if info.value.api_access:
            ROLE_API_PERMISSIONS[role].append({"id": access, "name": info.value.description})


def enum_to_str(enum, default_value: str = None) -> str | None:
    """
    Converts an enum to a string.
    """
    result = default_value
    if enum is not None:
        result = " ".join([item.capitalize() for item in enum.name.split("_")])
    return result


def get_all(session: Session, model: Type) -> Any:
    """
    Get all objects of class model from the database.
    """
    return session.query(model)


def get_by_id(session: Session, model: Type, item_id: uuid.UUID) -> Any:
    """
    Get an object of class model by its ID from the database.
    """
    result = session.get(model, item_id)
    if not result:
        raise NotFoundError(f"{model.__name__} with ID '{item_id}' not found.")
    return result


def update_database_record(
        session: Session,
        source: BaseModel,
        query_model: Type[BaseModel],
        source_model: Type[BaseModel],
        commit: bool,
        **kwargs
) -> SQLModel:
    """
    Updates the database record with the given source object.
    :param session: The database session used to update the record.
    :param source: The source object that contains the new values. The source's ID is used to identify the record in the
        database.
    :param query_model: The class of the object that is queried from the database.
    :param source_model: The class of the source object.
    :param commit: If True, the changes are committed to the database.
    :param kwargs: Additional keyword arguments that are passed to the update_attributes method.
    :return:
    """
    result = get_by_id(session=session, model=query_model, item_id=source.id)
    update_attributes(target=result, source=source, source_model=source_model, **kwargs)
    session.add(result)
    if commit:
        session.commit()
        session.refresh(result)
    return result


def update_attributes(
        target: SQLModel,
        source: BaseModel,
        source_model: Type[BaseModel],
        **kwargs
):
    """
    Updates the attributes of the target object with the attributes of the source object.
    :param target: The target object that is updated.
    :param source: The source object that contains the new values.
    :param source_model: The class of the source object.
    :param kwargs: Additional keyword arguments that are passed to the Pydantic model_dump method of the source object.
    :return:
    """
    # First, we create a temporary object that contains the new values. This allows us to apply all necessary
    # transformations using the Pydantic model_dump method.
    tmp = source_model(**source.model_dump(**kwargs)).model_dump(**kwargs)
    for key, value in tmp.items():
        if hasattr(target, key):
            setattr(target, key, value)
    return target


def sha256(string: str) -> str:
    """
    Returns the SHA-256 hash of a string.
    """
    return hashlib.sha256(string.strip().encode("utf-8")).hexdigest()


def convert_language_fields_dict(**kwargs: Dict[str, Dict[str, str]]):
    """
    The front-end sends language-specific fields as a dictionary of dictionaries where the parent dictionary contains
    the fields and the child dictionaries contain the language-specific values. This method converts this dictionary to
    a dictionary of dictionaries where the parent dictionary contains the language codes and the child dictionaries.
    """
    result = {}
    for field, details in kwargs.items():
        for language in details.keys():
            if language not in result:
                result[language] = {}
            result[language][field] = details[language]
    return result


def update_language_fields(
        session: Session,
        parent_object: SQLModel,
        create_object: Callable[[SQLModel, SQLModel, Dict[str, str]], SQLModel] = SQLModel,
        parent_object_attribute: str = "multi_language_fields",
        **kwargs: Dict[str, str]
) -> None:
    """
    Update the language-specific fields of a target object with the language-specific fields of a source object.
    """
    # Obtain all languages
    new_data = convert_language_fields_dict(**kwargs)
    for language_code in new_data.keys():
        multi_language_fields = getattr(parent_object, parent_object_attribute)
        result = list(filter(lambda item: item.language.language_code == language_code,
                             multi_language_fields if multi_language_fields else []))
        # In this case, the language details for the template procedure already exist.
        if result:
            if len(result) > 1:
                raise InvalidDataError(f"Duplicate language code '{language_code}'.")
            for name, value in new_data[language_code].items():
                setattr(result[0], name, value)
        else:
            # Otherwise, we need to create a new language details object.
            language = session.query(ReportLanguage).filter_by(language_code=language_code).one_or_none()
            if not language:
                raise InvalidDataError(f"Unknown language code '{language_code}'.")
            tmp = create_object(parent_object, language, **new_data[language_code])
            session.add(tmp)


def multi_language_field_model_validator(
        model: BaseModel,
        current_frame: FrameType,
        foreign_key_attribute: str = "multi_language_fields"
) -> Dict[str, str]:
    """
    Function can be used as a model validator to convert a language-specific field to the correct JSON format so that
    it can be consumed by the front-end.

    :param model: The object that contains a multi-language field that should be converted to a Dict.
    :param current_frame: The calling methods frame information. It allows extracting the calling method's name.
    :param foreign_key_attribute: The name of the object's attribute referencing the multi-language table.
    :return:
    """
    result = {}
    multi_language_field = current_frame.f_code.co_name
    if not hasattr(model, foreign_key_attribute):
        raise AttributeError(f"Attribute {multi_language_field} not found in {model.__class__.__name__}")
    language_objects = getattr(model, foreign_key_attribute)
    for language_object in language_objects:
        if language_object.language.language_code in result:
            raise KeyError(f"Language {language_object.language.language_code} already in language "
                           f"field {multi_language_field} of model f{model.__class__.__name__}.")
        language_value = getattr(language_object, multi_language_field)
        result[language_object.language.language_code] = language_value
    return result


def get_json_value(json_object: Dict, path: str, default_value=None):
    """
    This method returns the content of the attribute specified by the path.
    :param json_object: The JSON object that is searched
    :param path: Path (e.g. data/value/) that specifies which attribute shall be returned\
    :param default_value: The default value that shall be returned if the requested path does not exist
    :return:
    """
    if not path:
        return json_object
    path = path[1:] if path[0] == '/' else path
    current_position = json_object
    for value in path.split("/"):
        value = value.strip()
        if isinstance(current_position, dict) and value in current_position:
            current_position = current_position[value]
        else:
            current_position = None
            break
    return current_position if current_position is not None else default_value


def get_json_values(json_object: dict, path: str, default_value=None) -> list:
    """
    This method returns the content of the attribute specified by the path. This method is used, when the path
    variable contains a * in the list to traverse a list.
    :param json_object: The JSON object that is searched
    :param path: Path (e.g. data/value/) that specifies which attribute shall be returned\
    :param default_value: The default value that shall be returned if the requested path does not exist
    :return:
    """
    path = path[1:] if path[0] == '/' else path
    path_elements = [item.strip() for item in path.split("/")]
    path_elements_count = len(path_elements)
    current_position = json_object
    for i in range(0, path_elements_count):
        value = path_elements[i]
        if isinstance(current_position, dict) and value in current_position:
            current_position = current_position[value]
        elif isinstance(current_position, list) and value == "*":
            result = []
            for item in current_position:
                if isinstance(item, dict) and (i + 1) < path_elements_count:
                    tmp = get_json_value(json_object=item, path="/".join(path_elements[(i + 1):]))
                    if tmp is not None:
                        result.append(tmp)
            return result if result else default_value
        else:
            current_position = None
            break
    return [current_position] if current_position else default_value


def serialize_uuids(attribute: uuid.UUID | str | List[uuid.UUID] | List[str] | Set[uuid.UUID] | Set[str]) -> str | List[str]:
    """
    Serialize the UUIDs to a string.
    """
    if not attribute:
        return attribute
    elif isinstance(attribute, list):
        return [str(item) for item in attribute]
    elif isinstance(attribute, set):
        return [str(item) for item in attribute]
    return str(attribute)


def validate_uuids(attribute: uuid.UUID | str | List[uuid.UUID] | List[str] | Set[uuid.UUID] | Set[str]) -> uuid.UUID | List[uuid.UUID]:
    """
    Validate the UUIDs.
    """
    if not attribute:
        return attribute
    elif isinstance(attribute, list):
        return [uuid.UUID(item) if isinstance(item, str) else item for item in attribute]
    elif isinstance(attribute, set):
        return [uuid.UUID(item) if isinstance(item, str) else item for item in attribute]
    return uuid.UUID(attribute) if isinstance(attribute, str) else attribute
