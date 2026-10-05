"""Vulnerability management: CVEs, software, recommendations, remediation (Defender for Endpoint API)."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from .operations import operation
from .surface import Filter, MachineId, Skip, Surface, top
from .transport import MDE, JsonObject, capped, seg

CveId = Annotated[str, Field(description="The CVE ID, e.g. CVE-2024-1234.")]
SoftwareId = Annotated[str, Field(description="The software ID, e.g. microsoft-_-edge.")]
RecommendationId = Annotated[str, Field(description="The security recommendation ID.")]
ActivityId = Annotated[str, Field(description="The remediation activity ID.")]
_VULN = ("Vulnerability.Read.All",)
_SOFTWARE = ("Software.Read.All",)
_RECOMMENDATION = ("SecurityRecommendation.Read.All",)
_REMEDIATION = ("RemediationTasks.Read.All",)

_ASSESSMENTS = {
    "softwareInventory": "/machines/SoftwareInventoryByMachine",
    "softwareVulnerabilities": "/machines/SoftwareVulnerabilitiesByMachine",
    "secureConfiguration": "/machines/SecureConfigurationAssessmentByMachine",
    "browserExtensions": "/machines/BrowserExtensionsInventoryByMachine",
}


class Vulnerabilities(Surface):
    @operation(tool="defender_get_vulnerabilities", api="mde", permissions=_VULN)
    async def list_vulnerabilities(
        self,
        filter: Filter = None,
        top: Annotated[int, top("vulnerabilities", 25, 100)] = 25,
        skip: Skip = 0,
    ) -> JsonObject:
        """List the vulnerabilities that affect the organization, e.g. filter "severity eq
        'Critical'" or "publicExploit eq true"."""
        return await self._mde_list("/vulnerabilities", filter, top, skip)

    @operation(tool="defender_get_vulnerability_by_id", api="mde", permissions=_VULN)
    async def get_vulnerability(self, cve_id: CveId) -> JsonObject:
        """Get one vulnerability by CVE ID: severity, CVSS, exploit availability, exposed devices."""
        return await self._mde_get(f"/vulnerabilities/{seg(cve_id)}")

    @operation(tool="defender_get_machine_vulnerabilities", api="mde", permissions=_VULN)
    async def get_machine_vulnerabilities(
        self,
        machine_id: MachineId,
        top: Annotated[int, top("vulnerabilities", 25, 200)] = 25,
    ) -> JsonObject:
        """List the vulnerabilities that affect one device."""
        return await self._mde_bounded(f"/machines/{seg(machine_id)}/vulnerabilities", top)

    @operation(tool="defender_get_machines_by_vulnerability", api="mde", permissions=_VULN)
    async def get_machines_by_vulnerability(
        self,
        cve_id: CveId,
        top: Annotated[int, top("machines", 25, 200)] = 25,
    ) -> JsonObject:
        """List the devices exposed to a vulnerability."""
        return await self._mde_bounded(f"/vulnerabilities/{seg(cve_id)}/machineReferences", top)

    @operation(tool="defender_get_software", api="mde", permissions=_SOFTWARE)
    async def list_software(
        self,
        filter: Filter = None,
        top: Annotated[int, top("software entries", 25, 100)] = 25,
        skip: Skip = 0,
    ) -> JsonObject:
        """List the software inventory of the organization with weaknesses and exposed devices."""
        return await self._mde_list("/software", filter, top, skip)

    @operation(tool="defender_get_software_by_id", api="mde", permissions=_SOFTWARE)
    async def get_software(self, software_id: SoftwareId) -> JsonObject:
        """Get one software entry: vendor, weaknesses, exploit availability, exposed devices."""
        return await self._mde_get(f"/software/{seg(software_id)}")

    @operation(tool="defender_get_software_vulnerabilities", api="mde", permissions=_SOFTWARE)
    async def get_software_vulnerabilities(
        self,
        software_id: SoftwareId,
        top: Annotated[int, top("vulnerabilities", 25, 200)] = 25,
    ) -> JsonObject:
        """List the vulnerabilities of one software entry."""
        return await self._mde_bounded(f"/software/{seg(software_id)}/vulnerabilities", top)

    @operation(tool="defender_get_machines_by_software", api="mde", permissions=_SOFTWARE)
    async def get_machines_by_software(
        self,
        software_id: SoftwareId,
        top: Annotated[int, top("machines", 25, 200)] = 25,
    ) -> JsonObject:
        """List the devices that have a software installed."""
        return await self._mde_bounded(f"/software/{seg(software_id)}/machineReferences", top)

    @operation(tool="defender_get_software_version_distribution", api="mde", permissions=_SOFTWARE)
    async def get_software_version_distribution(self, software_id: SoftwareId) -> JsonObject:
        """Get the distribution of installed versions of a software."""
        return await self._mde_get(f"/software/{seg(software_id)}/distributions")

    @operation(tool="defender_get_recommendations", api="mde", permissions=_RECOMMENDATION)
    async def list_recommendations(
        self,
        filter: Filter = None,
        top: Annotated[int, top("recommendations", 25, 100)] = 25,
        skip: Skip = 0,
    ) -> JsonObject:
        """List security recommendations, e.g. filter "remediationType eq 'ConfigurationChange'"."""
        return await self._mde_list("/recommendations", filter, top, skip)

    @operation(tool="defender_get_recommendation_by_id", api="mde", permissions=_RECOMMENDATION)
    async def get_recommendation(self, recommendation_id: RecommendationId) -> JsonObject:
        """Get one security recommendation."""
        return await self._mde_get(f"/recommendations/{seg(recommendation_id)}")

    @operation(tool="defender_get_recommendation_machines", api="mde", permissions=_RECOMMENDATION)
    async def get_recommendation_machines(
        self,
        recommendation_id: RecommendationId,
        top: Annotated[int, top("machines", 25, 200)] = 25,
    ) -> JsonObject:
        """List the devices a security recommendation applies to."""
        return await self._mde_bounded(
            f"/recommendations/{seg(recommendation_id)}/machineReferences", top
        )

    @operation(
        tool="defender_get_recommendation_vulnerabilities", api="mde", permissions=_RECOMMENDATION
    )
    async def get_recommendation_vulnerabilities(
        self,
        recommendation_id: RecommendationId,
        top: Annotated[int, top("vulnerabilities", 25, 200)] = 25,
    ) -> JsonObject:
        """List the vulnerabilities a security recommendation addresses."""
        return await self._mde_bounded(
            f"/recommendations/{seg(recommendation_id)}/vulnerabilities", top
        )

    @operation(tool="defender_get_remediation_activities", api="mde", permissions=_REMEDIATION)
    async def list_remediation_activities(
        self,
        filter: Filter = None,
        top: Annotated[int, top("activities", 25, 100)] = 25,
    ) -> JsonObject:
        """List remediation activities with their status and due date."""
        return await self._mde_list("/remediationTasks", filter, top)

    @operation(tool="defender_get_remediation_activity_by_id", api="mde", permissions=_REMEDIATION)
    async def get_remediation_activity(self, activity_id: ActivityId) -> JsonObject:
        """Get one remediation activity."""
        return await self._mde_get(f"/remediationTasks/{seg(activity_id)}")

    @operation(tool="defender_get_remediation_exposed_devices", api="mde", permissions=_REMEDIATION)
    async def get_remediation_exposed_devices(
        self,
        activity_id: ActivityId,
        top: Annotated[int, top("machines", 25, 200)] = 25,
    ) -> JsonObject:
        """List the devices still exposed under a remediation activity."""
        return await self._mde_bounded(
            f"/remediationTasks/{seg(activity_id)}/machineReferences", top
        )

    @operation(
        tool="defender_export_assessment",
        api="mde",
        permissions=("Software.Read.All", "Vulnerability.Read.All"),
    )
    async def export_assessment(
        self,
        assessment_type: Annotated[
            Literal[
                "softwareInventory",
                "softwareVulnerabilities",
                "secureConfiguration",
                "browserExtensions",
            ],
            Field(description="Which per-device assessment to read."),
        ],
        top: Annotated[int, top("rows", 50, 500)] = 50,
    ) -> JsonObject:
        """Read a per-device assessment: one row per device and software, vulnerability,
        configuration or browser extension. The full export is large; this returns one bounded page
        and the next link."""
        return await self._api.request(
            MDE, "GET", _ASSESSMENTS[assessment_type], params={"$top": capped(top, 50, 500)}
        )
