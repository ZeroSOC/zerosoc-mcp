"""Incidents (Microsoft Graph security API, /security/incidents)."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field

from .errors import InvalidInputError, RedirectLoopError
from .evidence import inventory
from .operations import operation
from .surface import Classification, Determination, Filter, OrderBy, Skip, Surface, top
from .transport import GRAPH, JsonObject, capped, odata, seg

IncidentId = Annotated[
    str, Field(description="The incident ID, as shown in the Defender portal and the Graph API.")
]
IncidentStatus = Literal["active", "resolved", "inProgress", "redirected", "awaitingAction"]
IncidentSeverity = Literal["informational", "low", "medium", "high"]
"""What an incident's severity may be set to. Graph has no `critical` for an incident: a source
whose own scale has one maps it here, and says so where it records the mapping."""

RESOLVING_COMMENT_LIMIT = 30_000
"""What `resolvingComment` keeps. Measured against a live incident rather than read from the
documentation, which states no limit: past this the API answers 200 and stores the first 30,000
characters, so a caller that does not bound its own text is told the write succeeded and loses the
tail silently. Refused here instead — a truncation nobody sees is worse than an error."""

MAX_REDIRECTS = 10
MAX_ALERTS = 2000
MAX_ALERT_PAGES = 100
"""How many pages of the alert expansion are followed. The ceiling above bounds the alerts, which
only stops the walk while each page carries some: a page that answers with none and still offers a
next link would otherwise be followed forever. Both bounds are reported the same way."""
_SUMMARY = (
    "id",
    "title",
    "severity",
    "category",
    "status",
    "createdDateTime",
    "firstActivityDateTime",
    "lastActivityDateTime",
    "mitreTechniques",
    "serviceSource",
    "detectionSource",
    "detectorId",
)
_READ = ("SecurityIncident.Read.All",)
_WRITE = ("SecurityIncident.ReadWrite.All",)


class Incidents(Surface):
    async def incident_record(self, incident_id: str) -> JsonObject:
        """**The data plane**: the whole incident in one call, for a reader that maps it to a
        record rather than showing it to a model.

        The merge chain is followed to the master, the alerts come with it in a single
        ``$expand=alerts`` and the expansion's own paging is followed once. There is no ``top``,
        no ``skip`` and no summary: a deterministic reader needs all of it, reads it at one
        instant, and is not billed by the token. The agent-plane operations below page and
        summarize *this* record; none of them fetches the incident a second time.

        ``alertsTruncated`` is true where the incident has more alerts than this client reads to,
        and it is part of the record: a reader that drops it builds a Case silently missing alerts.
        """
        master, walked = await self._master(incident_id, expand_alerts=True)
        alerts, truncated = await self._all_alerts(master)
        return {
            "incidentId": str(master.get("id", incident_id)),
            "redirectedFrom": walked,
            "alertsTruncated": truncated,
            **{k: v for k, v in master.items() if not k.startswith("alerts")},
            "alerts": alerts,
        }

    @operation(tool="defender_list_incidents", api="graph", permissions=_READ)
    async def list_incidents(
        self,
        filter: Filter = None,
        top: Annotated[int, top("incidents", 25, 50)] = 25,
        orderby: OrderBy = None,
    ) -> JsonObject:
        """List incidents from Microsoft Defender XDR. Incidents group related alerts from all
        Defender workloads (endpoint, identity, email, cloud apps) into one attack story. Supports
        OData filtering with Graph camelCase values, e.g. "status eq 'active'", "severity eq 'high'",
        "lastUpdateDateTime gt 2026-01-01T00:00:00Z", "assignedTo eq 'analyst@contoso.com'". Use it
        to find incidents before drilling into one. A merged incident has status 'redirected' and
        names its master in redirectIncidentId."""
        return await self._api.request(
            GRAPH,
            "GET",
            "/security/incidents",
            params=odata(filter, capped(top, 25, 50), orderby=orderby),
        )

    @operation(tool="defender_get_incident", api="graph", permissions=_READ)
    async def get_incident(self, incident_id: IncidentId) -> JsonObject:
        """Get one incident as it is stored: severity, status, classification, determination, owner,
        custom tags, comment thread, timestamps, and redirectIncidentId when it was merged into
        another. The starting point of incident analysis; it does not follow merges (use
        defender_resolve_incident for that)."""
        return await self._api.request(GRAPH, "GET", f"/security/incidents/{seg(incident_id)}")

    @operation(tool="defender_resolve_incident", api="graph", permissions=_READ)
    async def resolve_incident(self, incident_id: IncidentId) -> JsonObject:
        """Follow the merge history of an incident to its master. Returns the master incident with
        incidentId (the master's ID) and redirectedFrom (the merged IDs walked, in order; empty when
        the incident is live). Writes made by this server already do this; call it to learn where
        an incident went."""
        master, walked = await self._master(incident_id)
        return {
            "incidentId": str(master.get("id", incident_id)),
            "redirectedFrom": walked,
            **master,
        }

    @operation(tool="defender_get_incident_alerts", api="graph", permissions=_READ)
    async def get_incident_alerts(
        self,
        incident_id: IncidentId,
        top: Annotated[int, top("alerts", 10, 50)] = 10,
        skip: Skip = 0,
        summary_only: Annotated[
            bool,
            Field(
                description="Only id, title, severity, category, status, detector, MITRE techniques and"
                " timestamps, without the evidence. Recommended first call on a large incident."
            ),
        ] = False,
    ) -> JsonObject:
        """Get the alerts of an incident, paged (skip/top), with their details: title, severity,
        category, MITRE techniques, detection source, timestamps and nested evidence. For the
        entities themselves prefer defender_get_incident_evidence, which flattens and de-duplicates
        the evidence of every alert in one call."""
        record = await self.incident_record(incident_id)
        alerts: list[dict[str, Any]] = list(record["alerts"])
        size, skip = capped(top, 10, 50), max(0, skip)
        page = alerts[skip : skip + size]
        return {
            "incidentId": record["incidentId"],
            "totalAlerts": len(alerts),
            "alertsTruncated": record["alertsTruncated"],
            "skip": skip,
            "top": size,
            "returned": len(page),
            "hasMore": skip + size < len(alerts),
            "alerts": [{k: a.get(k) for k in _SUMMARY} for a in page] if summary_only else page,
        }

    @operation(tool="defender_get_incident_evidence", api="graph", permissions=_READ)
    async def get_incident_evidence(
        self,
        incident_id: IncidentId,
        types: Annotated[
            list[str] | None,
            Field(
                description="Only these entity types, e.g. ['process', 'file']. Types: device, user,"
                " process, file, ip, url, registry_key, registry_value, mailbox, and any other evidence"
                " type the source reports. entityCount always covers the whole incident."
            ),
        ] = None,
        top: Annotated[int, top("entities", 200, 1000)] = 200,
        skip: Skip = 0,
    ) -> JsonObject:
        """The full evidence inventory of an incident: the portal's evidence view as one table. Pages
        through every alert and flattens the evidence into one row per evidence item, each joined to
        its device (by device ID, else through the alert) and listing the alerts that cite it. A row
        is the source's own unit: entityCount equals the portal's count of evidence items and is the
        number to reconcile; rowCount is the number of per-alert evidence rows. The source lists one
        process more than once when alerts describe it differently (no image file, another path, a
        different verdict): those rows share `instance` (device, PID, creation time), sameProcess
        groups them with their verdicts, and processInstanceCount is the number of real processes.
        Rows carry type, name, PID and parent PID, full command line and its decoded
        -EncodedCommand payload, creation times in UTC, SHA1/SHA256, path, user SID and UPN, device
        ID, IP, registry key and value, detailed roles, verdict and remediation status. Follows a
        merged incident to its master. These are the entities the alerts cite, not raw telemetry:
        processes the detection did not flag are not here."""
        record = await self.incident_record(incident_id)
        alerts, truncated = list(record["alerts"]), bool(record["alertsTruncated"])
        result = inventory(alerts)
        wanted = {t.strip().lower() for t in types or []}
        matching = [e for e in result.pop("entities") if not wanted or e["type"] in wanted]
        size, skip = capped(top, 200, 1000), max(0, skip)
        page = matching[skip : skip + size]
        note = (
            {
                "note": f"only the first {MAX_ALERTS} alerts were read: the counts are a lower bound,"
                " not the whole incident, and must not be reconciled against the source"
            }
            if truncated
            else {}
        )
        return {
            "incidentId": record["incidentId"],
            "redirectedFrom": record["redirectedFrom"],
            "alertsTruncated": truncated,
            **note,
            **result,
            "matching": len(matching),
            "skip": skip,
            "returned": len(page),
            "hasMore": skip + size < len(matching),
            "entities": page,
        }

    @operation(tool="defender_update_incident", api="graph", kind="write", permissions=_WRITE)
    async def update_incident(
        self,
        incident_id: IncidentId,
        status: Annotated[IncidentStatus | None, Field(description="Incident status.")] = None,
        assigned_to: Annotated[str | None, Field(description="Owner (UPN or email).")] = None,
        classification: Annotated[
            Classification | None, Field(description="Classification.")
        ] = None,
        determination: Annotated[Determination | None, Field(description="Determination.")] = None,
        custom_tags: Annotated[
            list[str] | None, Field(description="Custom tags; replaces the existing tag set.")
        ] = None,
        severity: Annotated[
            IncidentSeverity | None, Field(description="Incident severity.")
        ] = None,
        resolving_comment: Annotated[
            str | None,
            Field(
                description="Why the incident was resolved and classified as it was; single-valued"
                f" and overwritten on each write, up to {RESOLVING_COMMENT_LIMIT} characters."
            ),
        ] = None,
        description: Annotated[
            str | None,
            Field(
                description="The incident's description, shown in the portal. Whole-value replace:"
                " it discards whatever is there, including the text the product wrote."
            ),
        ] = None,
    ) -> JsonObject:
        """Update an incident (a triage write): status, assignee, classification, determination,
        custom tags, severity, the resolving comment and the description. If the incident was
        merged into another, the update is applied to the master incident and redirectedFrom says
        so.

        `resolving_comment` and `description` are single-valued and replace what is stored, unlike
        a comment, which is appended to a thread. `description` replaces text the product itself
        wrote, so a caller that means to keep the original reads it first.
        """
        if resolving_comment is not None and len(resolving_comment) > RESOLVING_COMMENT_LIMIT:
            raise InvalidInputError(
                f"resolving_comment is {len(resolving_comment)} characters and the source keeps"
                f" {RESOLVING_COMMENT_LIMIT}: it answers 200 and discards the rest without saying"
                " so, so bound the text before writing it"
            )
        body = {
            "status": status,
            "assignedTo": assigned_to,
            "classification": classification,
            "determination": determination,
            "customTags": custom_tags,
            "severity": severity,
            "resolvingComment": resolving_comment,
            "description": description,
        }
        body = {k: v for k, v in body.items() if v is not None}
        if not body:
            raise InvalidInputError("nothing to update: pass at least one property")
        master, walked = await self._master(incident_id)
        target = str(master.get("id", incident_id))
        updated = await self._api.request(
            GRAPH, "PATCH", f"/security/incidents/{seg(target)}", json=body
        )
        return {"incidentId": target, "redirectedFrom": walked, **updated}

    @operation(tool="defender_add_incident_comment", api="graph", kind="write", permissions=_WRITE)
    async def add_incident_comment(
        self,
        incident_id: IncidentId,
        comment: Annotated[str, Field(description="The comment text to append to the thread.")],
    ) -> JsonObject:
        """Append a comment to an incident's comment thread (a triage write), visible to analysts in
        the Defender portal. If the incident was merged into another, the comment is written on the
        master incident, where analysts will read it, and redirectedFrom says so."""
        master, walked = await self._master(incident_id)
        target = str(master.get("id", incident_id))
        thread = await self._api.request(
            GRAPH,
            "POST",
            f"/security/incidents/{seg(target)}/comments",
            json={"@odata.type": "microsoft.graph.security.alertComment", "comment": comment},
        )
        return {"incidentId": target, "redirectedFrom": walked, **thread}

    async def _master(
        self, incident_id: str, *, expand_alerts: bool = False
    ) -> tuple[JsonObject, list[str]]:
        """The incident after following `redirectIncidentId`, and the merged IDs walked to reach it."""
        params = {"$expand": "alerts"} if expand_alerts else None
        walked: list[str] = []
        current = incident_id
        while True:
            incident = await self._api.request(
                GRAPH, "GET", f"/security/incidents/{seg(current)}", params=params
            )
            target = incident.get("redirectIncidentId")
            if incident.get("status") != "redirected" or not target:
                return incident, walked
            walked.append(current)
            if str(target) in walked or len(walked) > MAX_REDIRECTS:
                raise RedirectLoopError(f"incident {incident_id}: merge chain {[*walked, target]}")
            current = str(target)

    async def _all_alerts(self, incident: JsonObject) -> tuple[list[dict[str, Any]], bool]:
        """Every alert of an expanded incident, and whether reading stopped at the ceiling. The
        expansion itself can be paged."""
        alerts: list[dict[str, Any]] = list(incident.get("alerts") or [])
        next_link = incident.get("alerts@odata.nextLink")
        pages = 0
        while next_link and len(alerts) < MAX_ALERTS and pages < MAX_ALERT_PAGES:
            page = await self._api.follow(GRAPH, str(next_link), "/security/incidents/alerts")
            alerts.extend(page.get("value") or [])
            next_link = page.get("@odata.nextLink")
            pages += 1
        return alerts[:MAX_ALERTS], bool(next_link) or len(alerts) > MAX_ALERTS
