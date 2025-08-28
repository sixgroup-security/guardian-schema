from sqlalchemy.engine import Connection
from . import DatabaseViewBase


class ProjectSummaryView(DatabaseViewBase):
    """
    Provides view for project summary
    """

    def __init__(self, connection: Connection):
        super().__init__(
            connection=connection,
            name="vw_project_summary",
            content="""
    WITH app_summary AS (
        SELECT
            p.id AS project_id,
            string_agg(a.application_id, ',') AS troux_ids
        FROM project p
            INNER JOIN applicationproject m ON m.project_id = p.id
            INNER JOIN application a ON m.application_id = a.id
            GROUP BY p.id
    ),
    test_reasons AS (
        SELECT
            p.id AS project_id,
            string_agg(t.name, ',') AS test_reasons
        FROM project p
            JOIN tagprojecttestreason m ON p.id = m.project_id
            JOIN tag t ON t.id = m.tag_id
            GROUP BY p.id
    ),
    test_environments AS (
        SELECT
            p.id AS project_id,
            string_agg(t.name, ',') AS test_environments
        FROM project p
            JOIN tagprojectenvironment m ON p.id = m.project_id
            JOIN tag t ON t.id = m.tag_id
            GROUP BY p.id
    ),
    general_tags AS (
        SELECT
            p.id AS project_id,
            string_agg(t.name, ',') AS general_tags
        FROM project p
            JOIN tagprojectgeneral m ON p.id = m.project_id
            JOIN tag t ON t.id = m.tag_id
            GROUP BY p.id
    ),
    classification_tags AS (
        SELECT
            p.id AS project_id,
            string_agg(t.name, ',') AS classification_tags
        FROM project p
            JOIN tagprojectclassification m ON p.id = m.project_id
            JOIN tag t ON t.id = m.tag_id
            GROUP BY p.id
    )
    SELECT
        p.id,
        p.name AS name,
        get_project_id(p) AS project_id,
        CASE
            WHEN p.project_type IS NULL THEN NULL
            WHEN p.project_type = 'attack_modelling' THEN 10
            WHEN p.project_type = 'bug_bounty' THEN 20
            WHEN p.project_type = 'red_team_exercise' THEN 30
            WHEN p.project_type = 'penetration_test' THEN 40
            WHEN p.project_type = 'purple_team_exercise' THEN 50
            WHEN p.project_type = 'security_assessment' THEN 60
            ELSE -1
        END AS project_type_value,
        p.project_type,
        CASE
            WHEN p.project_type IS NULL THEN NULL
            WHEN p.project_type = 'attack_modelling' THEN 'Attack Modelling'
            WHEN p.project_type = 'bug_bounty' THEN 'Bug Bounty'
            WHEN p.project_type = 'red_team_exercise' THEN 'Red Team Exercise'
            WHEN p.project_type = 'penetration_test' THEN 'Penetration Test'
            WHEN p.project_type = 'purple_team_exercise' THEN 'Purple Team Exercise'
            WHEN p.project_type = 'security_assessment' THEN 'Security Assessment'
            ELSE NULL
        END AS project_type_str,
        CASE
            WHEN p.state IS NULL THEN NULL
            WHEN p.state = 'backlog' THEN 10
            WHEN p.state = 'planning' THEN 20
            WHEN p.state = 'scheduled' THEN 25
            WHEN p.state = 'running' THEN 30
            WHEN p.state = 'reporting' THEN 40
            WHEN p.state = 'completed' THEN 50
            WHEN p.state = 'cancelled' THEN 60
            WHEN p.state = 'archived' THEN 70
            ELSE -1
        END AS state_value,
        p.state,
        CASE
            WHEN (p.state IS NULL) THEN NULL
            WHEN (p.state = 'backlog') THEN 'Backlog'
            WHEN (p.state = 'planning') THEN 'Planning'
            WHEN (p.state = 'scheduled') THEN 'Scheduled'
            WHEN (p.state = 'running') THEN 'Running'
            WHEN (p.state = 'reporting') THEN 'Reporting'
            WHEN (p.state = 'completed') THEN 'Completed'
            WHEN (p.state = 'cancelled') THEN 'Cancelled'
            WHEN (p.state = 'archived') THEN 'Archived'
            ELSE NULL::text
        END AS state_str,
        p.year,
        CONCAT('Q', EXTRACT(QUARTER FROM start_date)) AS quarter,
        p.start_date,
        p.end_date,
        p.completion_date,
        location.name AS country_name,
        location.code AS country_code,
        provider.name AS provider,
        customer.name AS customer,
        lead_tester.full_name AS lead_tester,
        manager.full_name AS security_partner,
        apps.troux_ids,
        test_reasons.test_reasons,
        test_environments.test_environments,
        general_tags.general_tags,
        classification_tags.classification_tags
    FROM project p
        LEFT JOIN entity provider ON provider.id = p.provider_id
        LEFT JOIN entity customer ON customer.id = p.customer_id
        LEFT JOIN country location ON location.id = p.location_id
        LEFT JOIN "user" lead_tester ON lead_tester.id = p.lead_tester_id
        LEFT JOIN "user" manager ON manager.id = p.manager_id
        LEFT JOIN app_summary apps ON p.id = apps.project_id
        LEFT JOIN test_reasons ON p.id = test_reasons.project_id
        LEFT JOIN test_environments ON p.id = test_environments.project_id
        LEFT JOIN general_tags ON p.id = general_tags.project_id
        LEFT JOIN classification_tags ON p.id = classification_tags.project_id;
""")
