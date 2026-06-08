"""
Detections module for Falcon MCP Server

This module provides tools for accessing and analyzing CrowdStrike Falcon detections.
"""

from textwrap import dedent
from typing import Any

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from mcp.types import ToolAnnotations
from pydantic import AnyUrl, Field

from falcon_mcp.common.logging import get_logger
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.resources.detections import (
    SEARCH_DETECTIONS_FQL_DOCUMENTATION,
)

logger = get_logger(__name__)


class DetectionsModule(BaseModule):
    """Module for accessing and analyzing CrowdStrike Falcon detections."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_tool(
            server=server,
            method=self.search_detections,
            name="search_detections",
        )

        self._add_tool(
            server=server,
            method=self.get_detection_details,
            name="get_detection_details",
        )

        self._add_tool(
            server=server,
            method=self.update_detections,
            name="update_detections",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register resources with the MCP server.

        Args:
            server: MCP server instance
        """
        search_detections_fql_resource = TextResource(
            uri=AnyUrl("falcon://detections/search/fql-guide"),
            name="falcon_search_detections_fql_guide",
            description="Contains the guide for the `filter` param of the `falcon_search_detections` tool.",
            text=SEARCH_DETECTIONS_FQL_DOCUMENTATION,
        )

        self._add_resource(
            server,
            search_detections_fql_resource,
        )

    def search_detections(
        self,
        filter: str | None = Field(
            default=None,
            description="FQL filter expression. See `falcon://detections/search/fql-guide` for syntax.",
            examples=["status:'new'+severity_name:'High'", "device.hostname:'DC*'"],
        ),
        limit: int = Field(
            default=10,
            ge=1,
            le=9999,
            description="The maximum number of detections to return in this response (default: 10; max: 9999). Use with the offset parameter to manage pagination of results.",
        ),
        offset: int | None = Field(
            default=None,
            description="The first detection to return, where 0 is the latest detection. Use with the offset parameter to manage pagination of results.",
        ),
        q: str | None = Field(
            default=None,
            description="Search all detection metadata for the provided string",
        ),
        sort: str | None = Field(
            default=None,
            description=dedent("""
                Sort detections using these options:

                timestamp: Timestamp when the detection occurred
                created_timestamp: When the detection was created
                updated_timestamp: When the detection was last modified
                severity: Severity level of the detection (1-100, recommended when filtering by severity)
                confidence: Confidence level of the detection (1-100)
                agent_id: Agent ID associated with the detection

                Sort either asc (ascending) or desc (descending).
                Both formats are supported: 'severity.desc' or 'severity|desc'

                When searching for high severity detections, use 'severity.desc' to get the highest severity detections first.
                For chronological ordering, use 'timestamp.desc' for most recent detections first.

                Examples: 'severity.desc', 'timestamp.desc'
            """).strip(),
            examples=["severity.desc", "timestamp.desc"],
        ),
        include_hidden: bool = Field(default=True),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Find detections by criteria and return their complete details.

        Use this to discover detections by severity, status, hostname, time range, or
        other attributes. Consult falcon://detections/search/fql-guide before constructing
        filter expressions. Returns full alert records including process context, device
        info, tactic/technique details, and threat classification.
        """
        detection_ids = self._base_search_api_call(
            operation="GetQueriesAlertsV2",
            search_params={
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "q": q,
                "sort": sort,
            },
            error_message="Failed to search detections",
        )

        # Handle search error - return with FQL guide
        if self._is_error(detection_ids):
            return self._format_fql_error_response(
                [detection_ids], filter, SEARCH_DETECTIONS_FQL_DOCUMENTATION
            )

        # Handle empty results - return with FQL guide
        if not detection_ids:
            return self._format_fql_error_response([], filter, SEARCH_DETECTIONS_FQL_DOCUMENTATION)

        # Get detection details - past FQL concerns, normal API flow
        details = self._base_get_by_ids(
            operation="PostEntitiesAlertsV2",
            ids=detection_ids,
            id_key="composite_ids",
            include_hidden=include_hidden,
        )

        if self._is_error(details):
            return [details]

        return details

    def get_detection_details(
        self,
        ids: list[str] = Field(
            description="Composite ID(s) to retrieve detection details for.",
        ),
        include_hidden: bool = Field(
            default=True,
            description="Whether to include hidden detections (default: True). When True, shows all detections including previously hidden ones for comprehensive visibility.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Retrieve details for detection IDs you already have.

        Use when you have specific composite detection ID(s). For discovering detections
        by criteria (severity, status, hostname, etc.), use falcon_search_detections
        instead. Returns full detection records.
        """
        logger.debug("Getting detection details for ID(s): %s", ids)

        return self._base_get_by_ids(
            operation="PostEntitiesAlertsV2",
            ids=ids,
            id_key="composite_ids",
            include_hidden=include_hidden,
        )

    def update_detections(
        self,
        ids: list[str] = Field(
            description="Composite detection ID(s) to update. Get these from `falcon_search_detections` or `falcon_get_detection_details`.",
        ),
        status: str | None = Field(
            default=None,
            description=(
                "New status for the detection(s). Valid values: 'new', 'in_progress', "
                "'true_positive', 'false_positive', 'ignored', 'closed', 'reopened'."
            ),
        ),
        comment: str | None = Field(
            default=None,
            description=(
                "Comment to append to the detection's audit trail. Strongly recommended "
                "when changing status — explains the triage decision."
            ),
        ),
        assigned_to_uuid: str | None = Field(
            default=None,
            description=(
                "Falcon user UUID to assign the detection(s) to. Use empty string to unassign. "
                "If you only have a username/email, you must resolve the UUID separately — "
                "this API does not accept usernames."
            ),
        ),
        show_in_ui: bool | None = Field(
            default=None,
            description=(
                "Whether the detection(s) should appear in the Falcon UI. "
                "Set to False to hide noisy or duplicated detections."
            ),
        ),
        tags_to_add: list[str] | None = Field(
            default=None,
            description="Tag values to add to the detection(s).",
        ),
        tags_to_remove: list[str] | None = Field(
            default=None,
            description="Tag values to remove from the detection(s).",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Update one or more detections (status, comment, assignee, visibility, tags).

        Wraps the Alerts v3 PATCH endpoint (`PatchEntitiesAlertsV3`). Common workflows:

        - **Close a benign detection**: status='closed' + comment='Ignored — benign activity per DLP triage policy'
        - **Assign for investigation**: status='in_progress' + assigned_to_uuid=<analyst uuid> + comment='Assigned to ...'
        - **Hide noisy duplicates**: show_in_ui=False + comment='Suppressed — duplicate of ...'

        At least one of status/comment/assigned_to_uuid/show_in_ui/tags_to_add/tags_to_remove
        must be provided. All updates apply to every ID in `ids`.
        """
        action_parameters: list[dict[str, str]] = []

        if status is not None:
            action_parameters.append({"name": "update_status", "value": status})
        if comment is not None:
            action_parameters.append({"name": "append_comment", "value": comment})
        if assigned_to_uuid is not None:
            # Per the API contract: empty string unassigns.
            action_parameters.append(
                {"name": "assign_to_uuid", "value": assigned_to_uuid}
            )
        if show_in_ui is not None:
            action_parameters.append(
                {"name": "show_in_ui", "value": "true" if show_in_ui else "false"}
            )
        if tags_to_add:
            for tag in tags_to_add:
                action_parameters.append({"name": "add_tag", "value": tag})
        if tags_to_remove:
            for tag in tags_to_remove:
                action_parameters.append({"name": "remove_tag", "value": tag})

        if not action_parameters:
            return [
                {
                    "error": (
                        "No update fields provided. Supply at least one of: status, "
                        "comment, assigned_to_uuid, show_in_ui, tags_to_add, tags_to_remove."
                    ),
                    "operation": "PatchEntitiesAlertsV3",
                }
            ]

        body = {
            "composite_ids": ids,
            "action_parameters": action_parameters,
        }

        logger.debug(
            "Updating %d detection(s) with action_parameters=%s",
            len(ids),
            action_parameters,
        )

        result = self._base_query_api_call(
            operation="PatchEntitiesAlertsV3",
            body_params=body,
            error_message="Failed to update detections",
            default_result=[],
        )

        if self._is_error(result):
            return [result]

        # The API returns an empty body on success; surface a useful confirmation.
        if not result:
            return [
                {
                    "status": "ok",
                    "updated_ids": ids,
                    "applied": action_parameters,
                }
            ]
        return result
