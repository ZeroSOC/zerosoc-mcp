"""Entity enrichment by file hash, domain, IP and user (Defender for Endpoint API)."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from .operations import operation
from .surface import Filter, Surface, top
from .transport import JsonObject, seg

FileHash = Annotated[str, Field(description="SHA1 or SHA256 of the file.")]
Domain = Annotated[str, Field(description="Domain name.")]
Ip = Annotated[str, Field(description="IP address.")]
UserId = Annotated[str, Field(description="User ID: the account name as Defender reports it.")]
_ALERTS = ("Alert.Read.All",)
_MACHINES = ("Machine.Read.All",)


class Entities(Surface):
    @operation(tool="defender_get_file_info", api="mde", permissions=("File.Read.All",))
    async def get_file_info(self, file_hash: FileHash) -> JsonObject:
        """Get what Defender knows about a file by hash: global prevalence and first seen, size,
        type, signer and issuer, determination. Only the hash leaves the environment."""
        return await self._mde_get(f"/files/{seg(file_hash)}")

    @operation(tool="defender_get_file_statistics", api="mde", permissions=("File.Read.All",))
    async def get_file_statistics(self, file_hash: FileHash) -> JsonObject:
        """Get the prevalence of a file in this organization and worldwide, with first and last
        seen. A file seen on one device and nowhere else is worth a closer look."""
        return await self._mde_get(f"/files/{seg(file_hash)}/stats")

    @operation(tool="defender_get_file_alerts", api="mde", permissions=_ALERTS)
    async def get_file_alerts(
        self,
        file_hash: FileHash,
        filter: Filter = None,
        top: Annotated[int, top("alerts", 25, 100)] = 25,
    ) -> JsonObject:
        """List the Defender for Endpoint alerts that involve a file."""
        return await self._mde_list(f"/files/{seg(file_hash)}/alerts", filter, top)

    @operation(tool="defender_get_file_machines", api="mde", permissions=_MACHINES)
    async def get_file_machines(
        self,
        file_hash: FileHash,
        filter: Filter = None,
        top: Annotated[int, top("machines", 25, 100)] = 25,
    ) -> JsonObject:
        """List the devices a file was seen on: the lateral scope of a hash."""
        return await self._mde_list(f"/files/{seg(file_hash)}/machines", filter, top)

    @operation(tool="defender_get_domain_alerts", api="mde", permissions=_ALERTS)
    async def get_domain_alerts(
        self,
        domain: Domain,
        filter: Filter = None,
        top: Annotated[int, top("alerts", 25, 100)] = 25,
    ) -> JsonObject:
        """List the Defender for Endpoint alerts that involve a domain."""
        return await self._mde_list(f"/domains/{seg(domain)}/alerts", filter, top)

    @operation(tool="defender_get_domain_machines", api="mde", permissions=_MACHINES)
    async def get_domain_machines(
        self,
        domain: Domain,
        filter: Filter = None,
        top: Annotated[int, top("machines", 25, 100)] = 25,
    ) -> JsonObject:
        """List the devices that communicated with a domain: the lateral scope of a domain."""
        return await self._mde_list(f"/domains/{seg(domain)}/machines", filter, top)

    @operation(tool="defender_get_domain_statistics", api="mde", permissions=("Url.Read.All",))
    async def get_domain_statistics(self, domain: Domain) -> JsonObject:
        """Get the prevalence of a domain in this organization, with first and last seen."""
        return await self._mde_get(f"/domains/{seg(domain)}/stats")

    @operation(tool="defender_get_ip_alerts", api="mde", permissions=_ALERTS)
    async def get_ip_alerts(
        self,
        ip: Ip,
        filter: Filter = None,
        top: Annotated[int, top("alerts", 25, 100)] = 25,
    ) -> JsonObject:
        """List the Defender for Endpoint alerts that involve an IP address."""
        return await self._mde_list(f"/ips/{seg(ip)}/alerts", filter, top)

    @operation(tool="defender_get_ip_statistics", api="mde", permissions=("Ip.Read.All",))
    async def get_ip_statistics(self, ip: Ip) -> JsonObject:
        """Get the prevalence of an IP address in this organization, with first and last seen."""
        return await self._mde_get(f"/ips/{seg(ip)}/stats")

    @operation(tool="defender_get_user_alerts", api="mde", permissions=_ALERTS)
    async def get_user_alerts(
        self,
        user_id: UserId,
        filter: Filter = None,
        top: Annotated[int, top("alerts", 25, 100)] = 25,
    ) -> JsonObject:
        """List the Defender for Endpoint alerts that involve a user."""
        return await self._mde_list(f"/users/{seg(user_id)}/alerts", filter, top)

    @operation(tool="defender_get_user_machines", api="mde", permissions=_MACHINES)
    async def get_user_machines(
        self,
        user_id: UserId,
        filter: Filter = None,
        top: Annotated[int, top("machines", 25, 100)] = 25,
    ) -> JsonObject:
        """List the devices a user logged on to: logon relationships, not role or privilege."""
        return await self._mde_list(f"/users/{seg(user_id)}/machines", filter, top)
