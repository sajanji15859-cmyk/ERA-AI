"""Reference workflows shipped with Phase 4C.

These are declarative, strict-schema definitions. Webpage content can never
define or modify a workflow — the definitions below are code that an operator
has reviewed. Secrets are referenced exclusively through opaque
``vault:browser/<name>`` references; nothing here carries plaintext secrets.

``login`` is the primary tested reference workflow (offline simulator). The
``search_and_extract`` and ``download_report`` definitions document how to
build additional workflows.
"""

from __future__ import annotations

from era.workflows.definition import WorkflowDefinition, WorkflowStep

# --------------------------------------------------------------------------- #
# Reference login workflow
# --------------------------------------------------------------------------- #
# 1. navigate to the login URL
# 2. fill the username field from vault:browser/<username_vault>
# 3. fill the password field from vault:browser/<password_vault>
# 4. submit with expect: navigation (url_contains the expected landing path)
# 5. verify a deterministic post-condition (extract the landing page DOM)
# 6. the engine emits a sanitized receipt on completion
# --------------------------------------------------------------------------- #
LOGIN_WORKFLOW = WorkflowDefinition(
    name="login",
    version=1,
    description=(
        "Sign into a public web app: navigate, fill credentials from the vault, "
        "submit with a navigation post-condition, then verify the landing page."
    ),
    params_schema={
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "username_vault": {"type": "string"},
            "password_vault": {"type": "string"},
            "expected_url_contains": {"type": "string"},
        },
        "required": ["url", "username_vault", "password_vault"],
    },
    steps=[
        WorkflowStep(
            id="nav",
            action="browser.navigate",
            params={"url": "{{url}}"},
            description="navigate to the login URL",
        ),
        WorkflowStep(
            id="fill_user",
            action="browser.fill",
            params={"value_ref": "{{username_vault}}"},
            target={"role": "textbox", "name": "Username", "input_type": "text"},
            description="fill the username from the vault",
        ),
        WorkflowStep(
            id="fill_pass",
            action="browser.fill",
            params={"value_ref": "{{password_vault}}"},
            target={"role": "textbox", "name": "Password", "input_type": "password"},
            description="fill the password from the vault",
        ),
        WorkflowStep(
            id="submit",
            action="browser.submit",
            params={},
            target={"role": "button", "name": "Submit", "tag": "button"},
            expect={"kind": "navigation", "url_contains": "{{expected_url_contains}}"},
            description="submit the login form and require a navigation post-condition",
        ),
        WorkflowStep(
            id="verify",
            action="browser.extract_dom",
            params={"max_chars": 2000},
            outputs={"landing_text": "text"},
            description="verify a deterministic post-condition on the landing page",
        ),
    ],
)

# --------------------------------------------------------------------------- #
# Reference search-and-extract workflow (documentation example)
# --------------------------------------------------------------------------- #
SEARCH_EXTRACT_WORKFLOW = WorkflowDefinition(
    name="search_and_extract",
    version=1,
    description=(
        "Open a search page, type a non-secret query into a declared text field, "
        "submit, and extract the results page as bounded markdown."
    ),
    params_schema={
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "query": {"type": "string"},
            "expected_url_contains": {"type": "string"},
        },
        "required": ["url", "query"],
    },
    steps=[
        WorkflowStep(id="nav", action="browser.navigate",
                     params={"url": "{{url}}"}),
        WorkflowStep(
            id="fill_query",
            action="browser.fill",
            params={"text": "{{query}}"},
            target={"role": "textbox", "input_type": "text"},
            description="fill a non-secret query into the search field",
        ),
        WorkflowStep(
            id="submit",
            action="browser.submit",
            params={},
            target={"role": "button"},
            expect={"kind": "navigation", "url_contains": "{{expected_url_contains}}"},
        ),
        WorkflowStep(
            id="extract",
            action="browser.extract_dom",
            params={"max_chars": 5000},
            outputs={"markdown": "markdown"},
        ),
    ],
)

# --------------------------------------------------------------------------- #
# Reference download workflow (documentation example)
# --------------------------------------------------------------------------- #
DOWNLOAD_WORKFLOW = WorkflowDefinition(
    name="download_report",
    version=1,
    description=(
        "Open a page containing a download link and save the artifact to the "
        "workspace under a workflow-supplied path (workspace-confined, size-bound)."
    ),
    params_schema={
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "path": {"type": "string"},
        },
        "required": ["url", "path"],
    },
    steps=[
        WorkflowStep(id="nav", action="browser.navigate",
                     params={"url": "{{url}}"}),
        WorkflowStep(
            id="grab",
            action="browser.download",
            params={"path": "{{path}}"},
            target={"role": "link"},
            description="download the artifact from a link on the page",
        ),
    ],
)

REFERENCE_WORKFLOWS: list[WorkflowDefinition] = [
    LOGIN_WORKFLOW,
    SEARCH_EXTRACT_WORKFLOW,
    DOWNLOAD_WORKFLOW,
]

__all__ = [
    "DOWNLOAD_WORKFLOW",
    "LOGIN_WORKFLOW",
    "REFERENCE_WORKFLOWS",
    "SEARCH_EXTRACT_WORKFLOW",
]
