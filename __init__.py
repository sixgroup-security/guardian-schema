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

import re
import json
import logging
import redis.asyncio as redis
import xml.etree.ElementTree as ET
from pathlib import Path
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import MultipleResultsFound
from sqlalchemy.engine import Engine

# Import all classes so that SQLAlchemy can create the tables
from .application import *
from .country import *
from .database.user_triggers import OnUserLockRevokeTokensTrigger
from .entity import *
from .project import *
from .project_comment import *
from .project_user import *
from .tagging import *
from .tagging.cvss import Cvss, create_cvss_v3
from .user import *
from .reporting.file.file import *
from .reporting.file.test_procedure import *
from .reporting.file.user import *
from .reporting.report import *
from schema.tagging.mitre_cwe import (
    CweWeakness, CweStatus, CweVulnerabilityMappingType, CweAbstractionType, CweBase, CweView, CweViewType,
    CweBaseRelationship, CweNatureType, CweOrdinalType, CweCategory, CweCategoryStatus
)
from schema.reporting.file.report import ReportFile
from .reporting.report_section_management.report_section import *
from .reporting.vulnerability.rating import *
from .reporting.vulnerability.playbook import *
from .reporting.vulnerability.test_procedure import *
from .reporting.vulnerability.test_procedure_playbook import *
from .reporting.vulnerability.test_procedure_vulnerability_template import *
from .reporting.vulnerability.vulnerability_template import *
# Import all functions and triggers
from schema.database.common import (
    UpdateApplicationDatesForApplicationIdFunction,
    UpdateApplicationDatesForProjectIdFunction,
    ChooseValueDependingOnConditionFunction,
    GetCvssSeverityValueFunction,
    GetCvssSeverityStringFunction,
    GetApplicationOverdueValueFunction,
    GetApplicationOverdueStringFunction,
    GetProjectIdFunction
)
from schema.database.application_triggers import (
    OnBeforeApplicationUpdateInsertTrigger,
    OnBeforeApplicationUpdateInsertCalculatePeriodicityTrigger,
    OnBeforeApplicationUpdateInsertCalculateOverdueStatusTrigger
)
from schema.database.project_triggers import (
    OnBeforeProjectUpdateInsertTrigger, OnAfterProjectUpdateTrigger,
    OnBeforeProjectUpdateInsertTrigger2,
    OnAfterProjectUpdateInsertDeleteTrigger
)
from schema.database.applicationproject_triggers import OnAfterApplicationProjectUpdateInsertDeleteTrigger
from schema.database.vulnerability_triggers import (
    OnAfterVulnerabilityUpdateInsertDeleteTrigger, UpdateVulnerabilityIdFunction
)
from schema.database.views.vw_project_summary import ProjectSummaryView
from schema.tagging.bugcrowd_vrt import (
    Vrt, VrtImport, VrtCategoryImport, VrtCategory, VrtSubCategory, VrtVariant, get_vrt
)

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


APP_DIRECTORY = Path(__file__).parent.parent
logger = logging.getLogger(__name__)
prod = os.getenv("ENV", "test").lower() == "prod"
if prod:
    load_dotenv(APP_DIRECTORY / ".env.db")
else:
    load_dotenv(APP_DIRECTORY / ".env.db.test")
load_dotenv(APP_DIRECTORY / ".env.redis")


class SettingsBase:
    """
    This class manages the settings that are required by the schema.
    """
    def __init__(self):
        # Database settings
        redis_timeout = os.getenv("REDIS_TIMEOUT")
        self.db_scheme = os.getenv("DIALECT", "postgresql")
        self.db_name = os.getenv("POSTGRES_DB")
        self.db_user = os.getenv("POSTGRES_USER")
        self.db_password = os.getenv("POSTGRES_PASSWORD")
        self.db_host = os.getenv("POSTGRES_HOST")
        self.db_port = int(os.getenv("POSTGRES_PORT", 5432))
        self.db_ssl = os.getenv("POSTGRES_USE_SSL", "true").lower() == "true"
        self.db_pool_size = int(os.getenv("POSTGRES_POOL_SIZE", 10))
        self.db_max_overflow = int(os.getenv("POSTGRES_MAX_OVERFLOW", 5))
        self.db_pool_timeout = int(os.getenv("POSTGRES_POOL_TIMEOUT", 60))
        self.db_pool_recycle = int(os.getenv("POSTGRES_POOL_RECYCLE", 1800))
        self.db_pool_pre_ping = os.getenv("POSTGRES_POOL_PRE_PING", "false").lower() == "true"
        self.db_echo_pool = os.getenv("POSTGRES_ECHO_POOL")  # Set to debug to debug reset-on-return events
        self.cert = os.getenv("SSL_CERT_FILE")
        # Redis
        self.redis_host = os.getenv("REDIS_HOST")
        self.redis_port = int(os.getenv("REDIS_PORT", 6379))
        self.redis_ssl = os.getenv("REDIS_USE_SSL", "true").lower() == "true"
        self.redis_timeout = int(redis_timeout) if redis_timeout and redis_timeout else None
        # Channel definitions
        self.redis_notify_user_channel = os.getenv("REDIS_NOTIFY_USER_CHANNEL")
        self.redis_report_channel = os.getenv("REDIS_REPORT_CHANNEL")
        # User definitions
        self.redis_user_notify_user_read = os.getenv("REDIS_USER_NOTIFY_USER_READ")
        self.redis_password_notify_user_read = os.getenv("REDIS_PASSWORD_NOTIFY_USER_READ")
        self.redis_user_notify_user_write = os.getenv("REDIS_USER_NOTIFY_USER_WRITE")
        self.redis_password_notify_user_write = os.getenv("REDIS_PASSWORD_NOTIFY_USER_WRITE")
        self.redis_user_report_read = os.getenv("REDIS_USER_REPORT_READ")
        self.redis_password_report_read = os.getenv("REDIS_PASSWORD_REPORT_READ")
        self.redis_user_report_write = os.getenv("REDIS_USER_REPORT_WRITE")
        self.redis_password_report_write = os.getenv("REDIS_PASSWORD_REPORT_WRITE")
        self.redis_ping = os.getenv("REDIS_PING", "false").lower() == "true"
        # Logging settings
        self.log_file = os.getenv("GUARDIAN_LOG_FILE")
        self.log_level = os.getenv("GUARDIAN_LOG_LEVEL", "INFO").upper()
        self.log_format = os.getenv(
            'GUARDIAN_LOG_FORMAT',
            '%(asctime)s [%(levelname)-8s] %(client_ip)-15s %(user_name)s - %(name)s - %(message)s'
        )
        self.log_date_format = os.getenv('GUARDIAN_LOG_DATE_FORMAT', '%Y-%m-%d %H:%M:%S')
        # Resource files
        self.country_file = os.path.join(os.getenv("DATA_LOCATION", ""), "countries.json")
        self.vrt_file = os.path.join(os.getenv("DATA_LOCATION", ""), "bugcrowd_vrt.json")
        self.vrt_cvss_v3_file = os.path.join(os.getenv("DATA_LOCATION", ""), "bugcrowd_vrt_cvss_v3.json")
        self.vrt_cwe_file = os.path.join(os.getenv("DATA_LOCATION", ""), "bugcrowd_vrt_cwe.json")
        self.cwe_weakness_files = [
            os.path.join(os.getenv("DATA_LOCATION", ""), item)
            for item in [
                "cwe_research_concepts.xml", "cwe_hardware_design.xml", "cwe_software_development.xml"
            ]
       ]
        self.cwe_category_files = [
            os.path.join(os.getenv("DATA_LOCATION", ""), item)
            for item in [
                "cwe_software_development_categories.xml"
            ]
       ]

    @property
    def database_uri(self):
        uri_string = f"{self.db_scheme}://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"
        return uri_string + f"?sslmode=verify-full&sslrootcert={self.cert}" if self.db_ssl else uri_string

    def create_redis(self, username: str, password: str, ping: bool = False) -> redis.Redis:
        """
        Creates a Redis client.
        """
        result = redis.Redis(
            host=self.redis_host,
            port=self.redis_port,
            username=username,
            password=password,
            ssl=self.redis_ssl,
            ssl_cert_reqs="none",
            socket_timeout=self.redis_timeout
        )
        if ping or self.redis_ping:
            result.ping()
        return result


def create_triggers(engine: Engine):
    with engine.connect() as connection:
        # PostgreSQL executes same triggers in their alphabetical order.
        # General helper functions (with no dependencies)
        ChooseValueDependingOnConditionFunction(connection).create()
        GetCvssSeverityValueFunction(connection).create()
        GetCvssSeverityStringFunction(connection).create()
        GetApplicationOverdueValueFunction(connection).create()
        GetApplicationOverdueStringFunction(connection).create()
        GetProjectIdFunction(connection).create()
        # PostgreSQL executes same triggers in their alphabetical order.
        UpdateVulnerabilityIdFunction(connection).create()
        UpdateApplicationDatesForApplicationIdFunction(connection).create()
        UpdateApplicationDatesForProjectIdFunction(connection).create()
        OnAfterVulnerabilityUpdateInsertDeleteTrigger(connection).create()  # on_07_after_vulnerability_update_insert_delete
        OnBeforeApplicationUpdateInsertCalculatePeriodicityTrigger(connection).create()  # on_01_before_application_update_insert
        OnBeforeApplicationUpdateInsertTrigger(connection).create()  # on_10_before_application_update_insert
        OnAfterApplicationProjectUpdateInsertDeleteTrigger(connection).create()  # on_03_after_applicationproject_change_trigger
        OnAfterProjectUpdateInsertDeleteTrigger(connection).create()  # on_05_after_project_change_trigger
        OnBeforeProjectUpdateInsertTrigger2(connection).create()  # on_04_before_project_increment_update_insert
        OnBeforeApplicationUpdateInsertCalculateOverdueStatusTrigger(connection).create()  # on_20_before_application_update_insert
        OnBeforeProjectUpdateInsertTrigger(connection).create()  # on_01_before_project_update_insert
        OnAfterProjectUpdateTrigger(connection).create()  # on_02_after_project_update
        OnUserLockRevokeTokensTrigger(connection).create()  # on_100_user_lock_revoke_tokens_trigger
        connection.commit()


def drop_triggers(engine: Engine):
    with engine.connect() as connection:
        # Specific functions and triggers
        OnUserLockRevokeTokensTrigger(connection).drop()  # on_100_user_lock_revoke_tokens_trigger
        OnAfterProjectUpdateTrigger(connection).drop()  # on_02_after_project_update
        OnBeforeProjectUpdateInsertTrigger(connection).drop()  # on_01_before_project_update_insert
        OnBeforeApplicationUpdateInsertCalculateOverdueStatusTrigger(connection).drop()  # on_20_before_application_update_insert
        OnBeforeApplicationUpdateInsertTrigger(connection).drop()  # on_10_before_application_update_insert
        OnAfterProjectUpdateInsertDeleteTrigger(connection).drop()  # on_05_after_project_change_trigger
        OnBeforeProjectUpdateInsertTrigger2(connection).drop()  # on_04_before_project_increment_update_insert
        OnAfterApplicationProjectUpdateInsertDeleteTrigger(connection).drop()  # on_03_after_applicationproject_change_trigger
        OnBeforeApplicationUpdateInsertCalculatePeriodicityTrigger(connection).drop()  # on_01_before_application_update_insert
        OnAfterVulnerabilityUpdateInsertDeleteTrigger(connection).drop()  # on_07_after_vulnerability_update_insert_delete
        UpdateApplicationDatesForProjectIdFunction(connection).drop()
        UpdateApplicationDatesForApplicationIdFunction(connection).drop()
        UpdateVulnerabilityIdFunction(connection).drop()
        # General helper functions (with no dependencies)
        ChooseValueDependingOnConditionFunction(connection).drop()
        GetCvssSeverityValueFunction(connection).drop()
        GetCvssSeverityStringFunction(connection).drop()
        GetApplicationOverdueValueFunction(connection).drop()
        GetApplicationOverdueStringFunction(connection).drop()
        GetProjectIdFunction(connection).drop()
        connection.commit()


def create_views(engine: Engine):
    with engine.connect() as connection:
        ProjectSummaryView(connection).create()
        connection.commit()


def drop_views(engine: Engine):
    with engine.connect() as connection:
        # ProjectSummaryView must be dropped last as other views might depend on it
        ProjectSummaryView(connection).drop()
        connection.commit()


def drop_procedures(engine: Engine):
    with engine.connect() as connection:
        ...


base_settings = SettingsBase()
engine = create_engine(
    base_settings.database_uri,
    pool_size=base_settings.db_pool_size,
    max_overflow=base_settings.db_max_overflow,
    pool_timeout=base_settings.db_pool_timeout,
    pool_recycle=base_settings.db_pool_recycle,
    echo_pool=base_settings.db_echo_pool,
    pool_pre_ping=base_settings.db_pool_pre_ping
)
engine.connect()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def drop_db_and_tables():
    try:
        # Drop all views
        drop_views(engine)
        drop_triggers(engine)
        drop_procedures(engine)
        # Drop all tables (if dropping views or procedures fails, then we also cannot drop tables)
        SQLModel.metadata.drop_all(engine)
    except Exception as ex:
        logger.exception(ex)


def create_db_and_tables():
    # Create all tables
    SQLModel.metadata.create_all(engine)
    # Create all functions and triggers
    create_triggers(engine)
    # Create all views
    create_views(engine)


def get_db():
    """
    Dependency to allow FastAPI endpoints to access the database.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def import_countries():
    """
    Import all countries from the countries.json file.
    """
    import json
    with SessionLocal() as session:
        with open(base_settings.country_file, "r") as file:
            for item in json.load(file):
                country = Country(**item)
                # We ensure that Spain and Switzerland are displayed first in the list.
                country.default = country.code in ["CH", "ES"]
                result = session.query(Country).filter_by(code=country.code).one_or_none()
                if not result:
                    session.add(country)
            session.commit()


def _create_vrt(
        session: Session,
        release_date: datetime,
        category: VrtCategory,
        cvss_object: dict | None = None,
        cwe_object: dict | None = None,
        sub_category: VrtSubCategory | None = None,
        variant: VrtVariant | None = None,
        priority: int | None = None
):
    """
    Creates a variant record based on the given data.
    """
    result = None
    # Create/update the CVSS record if available
    if cvss_object:
        cvss_v3_vector = get_vrt_mapping(
            json_object=cvss_object,
            vrt_category=category,
            vrt_sub_category=sub_category,
            vrt_variant=variant,
            key="cvss_v3"
        )
        result = create_cvss_v3(session=session, cvss_v3_vector=cvss_v3_vector)
    # Create/update the VRT record
    if vrt := get_vrt(
        session=session,
        category_id=category.vrt_id,
        sub_category_id=sub_category.vrt_id if sub_category else None,
        variant_id=variant.vrt_id if variant else None,
        priority=priority
    ).one_or_none():
        vrt.cvss = result
        vrt.release_date = release_date
        session.add(vrt)
    else:
        vrt = Vrt(
            category=category,
            sub_category=sub_category,
            variant=variant,
            priority=priority,
            cvss=result,
            release_date=release_date
        )
        session.add(vrt)
        session.flush()
    if cwe_object:
        items = get_vrt_mapping(
            json_object=cwe_object,
            vrt_category=category,
            vrt_sub_category=sub_category,
            vrt_variant=variant,
            key="cwe"
        )
        for item in (items or []):
            if match := re.match(r"^CWE-(?P<id>\d+)$", item, flags=re.IGNORECASE):
                cwe_id = match.group("id")
                if cwes := session.query(CweWeakness).filter_by(cwe_id=cwe_id).all():
                    if len(cwes) > 1:
                        logger.warning(f"CWE weakness {cwe_id} exists more than once.")
                    elif len(cwes) == 1:
                        vrt.cwes.append(cwes[0])
                        session.flush()
                    else:
                        logger.warning(f"CWE weakness {cwe_id} not found.")


def get_vrt_mapping(
        json_object: dict,
        vrt_category: VrtCategory,
        vrt_sub_category: VrtSubCategory | None = None,
        vrt_variant: VrtVariant | None = None,
        key: str = "cvss_v3"
) -> str | None:
    """
    Returns the CVSS vector for the given VRT data.
    """
    category = [item for item in json_object if item["id"] == vrt_category.vrt_id]
    if len(category) > 1:
        raise MultipleResultsFound(f"Multiple results found for category_id={vrt_category.vrt_id}")
    if len(category) == 0:
        return None
    category = category[0]
    category_vector = category.get(key)
    if vrt_sub_category:
        if "children" not in category:
            return category_vector
        sub_category = [item for item in category["children"] if item["id"] == vrt_sub_category.vrt_id]
        if len(sub_category) > 1:
            raise MultipleResultsFound(f"Multiple results found for sub_category_id={vrt_sub_category.vrt_id}")
        if len(sub_category) == 0:
            return category_vector
        sub_category = sub_category[0]
        sub_category_vector = sub_category.get(key)
        sub_category_vector = sub_category_vector if sub_category_vector else category_vector
        if vrt_variant:
            if "children" not in sub_category:
                return sub_category_vector
            variant = [item for item in sub_category["children"] if item["id"] == vrt_variant.vrt_id]
            if len(variant) > 1:
                raise MultipleResultsFound(f"Multiple results found for variant_id={vrt_variant.vrt_id}")
            if len(variant) == 0:
                return sub_category_vector
            variant = variant[0]
            variant_vector = variant.get(key)
            return variant_vector if variant_vector else sub_category_vector
        return sub_category_vector
    return category_vector


def import_vrt_categories():
    """
    Import all VRT categories from the vulnerability-rating-taxonomy.json file.
    """
    with SessionLocal() as session:
        with open(base_settings.vrt_file, "r") as file:
            json_object = json.load(file)
        with open(base_settings.vrt_cvss_v3_file, "r") as file:
            cvss_object = json.load(file).get("content", [])
        with open(base_settings.vrt_cwe_file, "r") as file:
            cwe_object = json.load(file).get("content", [])
        if "content" in json_object:
            vrt_objects = VrtImport(**json_object)
            #release_date = vrt_objects.release_date
            release_date = datetime.now()
            for category in vrt_objects.content:
                if category.priority:
                    raise ValueError("Category priority must be None.")
                vrt_category = session.query(VrtCategory).filter_by(vrt_id=category.vrt_id).one_or_none()
                if vrt_category:
                    vrt_category.name = category.name
                    vrt_category.release_date = release_date
                else:
                    vrt_category = VrtCategory(**category.model_dump(), release_date=release_date)
                    session.add(vrt_category)
                if category.children:
                    for sub_category in category.children:
                        vrt_sub_category = (
                            session.query(VrtSubCategory).filter_by(vrt_id=sub_category.vrt_id).one_or_none()
                        )
                        if vrt_sub_category:
                            vrt_sub_category.name = sub_category.name
                            vrt_sub_category.release_date = release_date
                        else:
                            vrt_sub_category = VrtSubCategory(
                                **sub_category.model_dump(),
                                release_date=release_date
                            )
                            session.add(vrt_sub_category)
                            session.flush()
                        if sub_category.children:
                            for variant in sub_category.children:
                                vrt_variant = (
                                    session.query(VrtVariant).filter_by(vrt_id=variant.vrt_id).one_or_none()
                                )
                                if vrt_variant:
                                    vrt_variant.name = variant.name
                                    vrt_variant.release_date = release_date
                                else:
                                    vrt_variant = VrtVariant(**variant.model_dump(), release_date=release_date)
                                    session.add(vrt_variant)
                                    session.flush()
                                _create_vrt(
                                    session=session,
                                    release_date=release_date,
                                    category=vrt_category,
                                    sub_category=vrt_sub_category,
                                    variant=vrt_variant,
                                    cvss_object=cvss_object,
                                    cwe_object=cwe_object,
                                    priority=variant.priority
                                )
                        else:
                            _create_vrt(
                                session=session,
                                release_date=release_date,
                                category=vrt_category,
                                sub_category=vrt_sub_category,
                                cvss_object=cvss_object,
                                cwe_object=cwe_object,
                                priority=sub_category.priority
                            )
                else:
                    _create_vrt(
                        session=session,
                        release_date=release_date,
                        category=vrt_category,
                        cvss_object=cvss_object,
                        cwe_object=cwe_object
                    )
        session.commit()


def create_cwe_views(session: Session):
    """
    In CWE, not all CWE IDs for weakness are unique. Nevertheless, each of them is assigned to a view and within them
    they are. This method creates these views so that weaknesses can be assigned to them.
    """
    cwes = [
        CweView(
            cwe_id=1000,
            name="Research Concepts",
            mapping=CweVulnerabilityMappingType.prohibited,
            type=CweViewType.graph,
            objective="This view is intended to facilitate research into weaknesses, including their "
                      "inter-dependencies, and can be leveraged to systematically identify theoretical gaps "
                      "within CWE. It is mainly organized according to abstractions of behaviors instead of "
                      "how they can be detected, where they appear in code, or when they are introduced in "
                      "the development life cycle. By design, this view is expected to include every weakness "
                      "within CWE."
        ),
        CweView(
            cwe_id=1194,
            name="Hardware Design",
            mapping=CweVulnerabilityMappingType.prohibited,
            type=CweViewType.graph,
            objective="This view organizes weaknesses around concepts that are frequently used or encountered in "
                      "hardware design. Accordingly, this view can align closely with the perspectives of designers, "
                      "manufacturers, educators, and assessment vendors. It provides a variety of categories that "
                      "are intended to simplify navigation, browsing, and mapping."
        ),
        CweView(
            cwe_id=699,
            name="Software Development",
            mapping=CweVulnerabilityMappingType.prohibited,
            type=CweViewType.graph,
            objective="This view organizes weaknesses around concepts that are frequently used or encountered in "
                      "software development. This includes all aspects of the software development lifecycle "
                      "including both architecture and implementation. Accordingly, this view can align closely with "
                      "the perspectives of architects, developers, educators, and assessment vendors. It provides a "
                      "variety of categories that are intended to simplify navigation, browsing, and mapping."
        ),
    ]
    if session.query(CweBase).count() == 0:
        for item in cwes:
            session.add(item)
        session.flush()


def import_cwe_weaknesses():
    """
    Import all CWE weaknesses from the XML file.
    """
    catalog_name_re = re.compile(r"^VIEW LIST: CWE-(?P<cwe>\d+): (?P<name>.+)$")
    with SessionLocal() as session:
        # Create parent views
        create_cwe_views(session)
        # Create all weaknesses
        for file_path in base_settings.cwe_weakness_files:
            tree = ET.parse(file_path)
            root = tree.getroot()
            match = catalog_name_re.match(root.attrib.get("Name", ""))
            version = float(root.attrib["Version"])
            if match:
                parent_cwe_id = int(match.group("cwe"))
                parent = session.query(CweView).filter_by(cwe_id=parent_cwe_id).one_or_none()
                if not parent:
                    raise ValueError(f"Parent CWE ID {parent_cwe_id} not found.")
            else:
                raise ValueError(f"The CWE file {file_path} cannot be parsed.")
            # Define the XML namespace
            namespace = {'cwe': 'http://cwe.mitre.org/cwe-7'}
            get_child = lambda x, y: x.find(f"cwe:{y}", namespace)
            for item in root.find('cwe:Weaknesses', namespace).findall('cwe:Weakness', namespace):
                item_id = int(item.get("ID"))
                item_abstraction = item.get("Abstraction")
                tmp = get_child(item, "Mapping_Notes")
                mapping = get_child(tmp, "Usage") if tmp else None
                mapping = CweVulnerabilityMappingType[mapping.text.replace("-", "_").lower()]
                abstraction_str = item_abstraction.lower()
                abstraction = CweAbstractionType["class_" if abstraction_str == "class" else abstraction_str]
                weakness = session.query(CweWeakness).filter_by(cwe_id=item_id).one_or_none()
                if not weakness:
                    weakness = CweWeakness(
                        cwe_id=item_id,
                        version=version,
                        name=item.get("Name"),
                        status=CweStatus[item.get("Status").lower()],
                        description=get_child(item, "Description").text,
                        abstraction=abstraction,
                        mapping=mapping
                    )
                    session.add(weakness)
                    session.add(CweBaseRelationship(
                        nature=CweNatureType.member_of_primary,
                        source=weakness,
                        destination=parent
                    ))
                    session.flush()
                elif not session.query(CweBaseRelationship).filter_by(
                        source_id=weakness.id,
                        destination_id=parent.id
                    ).one_or_none():
                        session.add(CweBaseRelationship(
                            nature=CweNatureType.member_of_primary,
                            source=weakness,
                            destination=parent
                        ))
        session.commit()


def import_cwe_categories():
    """
    Import all CWE categories from the XML file.
    """
    catalog_name_re = re.compile(r"^VIEW LIST: CWE-(?P<cwe>\d+): (?P<name>.+)$")
    with SessionLocal() as session:
        # Create all categories
        for file_path in base_settings.cwe_category_files:
            tree = ET.parse(file_path)
            root = tree.getroot()
            match = catalog_name_re.match(root.attrib.get("Name", ""))
            version = float(root.attrib["Version"])
            if match:
                parent_cwe_id = int(match.group("cwe"))
                parent = session.query(CweView).filter_by(cwe_id=parent_cwe_id).one_or_none()
                if not parent:
                    raise ValueError(f"Parent CWE ID {parent_cwe_id} not found.")
            else:
                raise ValueError(f"The CWE file {file_path} cannot be parsed.")
            # Define the XML namespace
            namespace = {'cwe': 'http://cwe.mitre.org/cwe-7'}
            get_child = lambda x, y: x.find(f"cwe:{y}", namespace)
            for item in root.find('cwe:Categories', namespace).findall('cwe:Category', namespace):
                item_id = int(item.get("ID"))
                name = item.get("Name")
                status = item.get("Status")
                summary = get_child(item, "Summary").text
                mapping_notes = get_child(item, "Mapping_Notes")
                mapping = get_child(mapping_notes, "Usage").text
                if not session.query(CweCategory).filter_by(cwe_id=item_id).one_or_none():
                    category = CweCategory(
                        name=name,
                        version=version,
                        cwe_id=item_id,
                        status=CweCategoryStatus[status.lower()],
                        mapping=CweVulnerabilityMappingType[mapping.lower()],
                        summary=summary
                    )
                    session.add(category)
                    session.add(
                        CweBaseRelationship(
                            nature=CweNatureType.member_of_primary,
                            source=category,
                            destination=parent
                        )
                    )
                    for child in get_child(item, "Relationships"):
                        weakness_id = int(child.get("CWE_ID"))
                        if not (weakness := session.query(CweWeakness).filter_by(cwe_id=weakness_id).one_or_none()):
                            raise ValueError(f"CWE weakness {weakness_id} not found.")
                        session.add(
                            CweBaseRelationship(
                                source=weakness,
                                destination=category,
                                nature=CweNatureType.belongs_to
                            )
                        )
        session.commit()


def init_db(
        drop_tables: bool = False,
        create_tables: bool = False,
        load_data: bool = False
):
    """
    Initializes the database.
    """
    if drop_tables:
        drop_db_and_tables()
    if create_tables:
        create_db_and_tables()
    if load_data:
        # Initialize static lookup tables
        import_countries()
        import_cwe_weaknesses()
        import_cwe_categories()
        import_vrt_categories()
