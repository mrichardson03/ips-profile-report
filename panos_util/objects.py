from __future__ import absolute_import, annotations, division, print_function

from collections import namedtuple
from xml.etree.ElementTree import Element

from . import strip_empty


class VulnerabilityProfile:
    """Class representing a vulnerability profile."""

    def __init__(self, name, rules):
        self.name = name
        self.rules = rules

    def blocks_criticals(self) -> bool:
        """Returns True if this profile has a rule that blocks critical events."""
        for rule in self.rules:
            if rule.blocks_criticals():
                return True
        return False

    def blocks_high(self) -> bool:
        """Returns True if this profile has a rule that blocks high events."""
        for rule in self.rules:
            if rule.blocks_high():
                return True
        return False

    def blocks_medium(self) -> bool:
        """Returns True if this profile has a rule that blocks medium events."""
        for rule in self.rules:
            if rule.blocks_medium():
                return True
        return False

    def alert_only(self) -> bool:
        """Returns True if this profile has only alert rules."""
        if len(self.rules) > 0:
            for rule in self.rules:
                if not rule.alert_only():
                    return False
            return True
        else:
            return False

    @staticmethod
    def create_from_element(e: Element) -> VulnerabilityProfile:
        """Create VulnerabilityProfile from XML element."""
        name = e.get("name")

        rules = []
        for rule in e.findall(".//rules/entry"):
            r = VulnerabilityProfileRule.create_from_element(rule)
            rules.append(r)

        return VulnerabilityProfile(name, rules)


class DefaultVulnerabilityProfile(VulnerabilityProfile):
    """
    Class representing the vulnerability profile 'default'.

    This profile does not actually exist in the config, so it is recreated here.
    """

    def __init__(self):
        pass

    @property
    def name(self) -> str:
        return "default"

    def blocks_criticals(self) -> bool:
        """Returns True if this profile has a rule that blocks critical events."""
        return False

    def blocks_high(self) -> bool:
        """Returns True if this profile has a rule that blocks high events."""
        return False

    def blocks_medium(self) -> bool:
        """Returns True if this profile has a rule that blocks medium events."""
        return False

    def alert_only(self) -> bool:
        """Returns True if this profile has only alert rules."""
        return False


class StrictVulnerabilityProfile(VulnerabilityProfile):
    """
    Class representing the vulnerability profile 'strict'.

    This profile does not actually exist in the config, so it is recreated here.
    """

    def __init__(self):
        pass

    @property
    def name(self) -> str:
        return "strict"

    def blocks_criticals(self) -> bool:
        """Returns True if this profile has a rule that blocks critical events."""
        return True

    def blocks_high(self) -> bool:
        """Returns True if this profile has a rule that blocks high events."""
        return True

    def blocks_medium(self) -> bool:
        """Returns True if this profile has a rule that blocks medium events."""
        return True

    def alert_only(self) -> bool:
        """Returns True if this profile has only alert rules."""
        return False


class VulnerabilityProfileRule(
    namedtuple(
        "VulnerabilityProfileRule",
        [
            "name",
            "vendor_id",
            "cve",
            "severity",
            "action",
            "threat_name",
            "host",
            "category",
            "packet_capture",
        ],
    )
):
    """Class representing a rule in a vulnerability profile."""

    def blocks_criticals(self) -> bool:
        """Returns True if a block action would be taken on critical events."""
        if self.severity is not None and "critical" in self.severity:
            if self.action is not None and self.action in [
                "block-ip",
                "drop",
                "reset-both",
                "reset-client",
                "reset-server",
            ]:
                return True

        return False

    def blocks_high(self) -> bool:
        """Returns True if a block action would be taken on high events."""
        if self.severity is not None and "high" in self.severity:
            if self.action is not None and self.action in [
                "block-ip",
                "drop",
                "reset-both",
                "reset-client",
                "reset-server",
            ]:
                return True

        return False

    def blocks_medium(self) -> bool:
        """Returns True if a block action would be taken on medium events."""
        if self.severity is not None and "medium" in self.severity:
            if self.action is not None and self.action in [
                "block-ip",
                "drop",
                "reset-both",
                "reset-client",
                "reset-server",
            ]:
                return True

        return False

    def alert_only(self) -> bool:
        """Returns True if an alert action would be taken on events."""
        if self.action == "alert":
            return True
        else:
            return False

    @staticmethod
    def create_from_element(e: Element) -> VulnerabilityProfileRule:
        """Create VulnerabilityProfileRule from XML element."""
        name = e.get("name")

        vendor_ids = []
        for vendor_id in e.findall(".//vendor-id/member"):
            vendor_ids.append(vendor_id.text)

        severities = []
        for severity in e.findall(".//severity/member"):
            severities.append(severity.text)

        cve_ids = []
        for cve in e.findall(".//cve/member"):
            cve_ids.append(cve.text)

        action = None
        if e.find(".//action/") is not None:
            action = e.find(".//action/").tag

        threat_name = strip_empty(e.findtext(".//threat-name"))
        host = strip_empty(e.findtext(".//host"))
        category = strip_empty(e.findtext(".//category"))
        packet_capture = strip_empty(e.findtext(".//packet-capture"))

        return VulnerabilityProfileRule(
            name,
            vendor_ids,
            cve_ids,
            severities,
            action,
            threat_name,
            host,
            category,
            packet_capture,
        )


class VulnerabilitySignature(
    namedtuple(
        "VulnerabilitySignature",
        [
            "threat_id",
            "name",
            "vendor_id",
            "cve_id",
            "category",
            "severity",
            "min_version",
            "max_version",
            "affected_host",
            "default_action",
        ],
    )
):
    """Class representing a vulnerability signature."""

    @staticmethod
    def create_from_element(e: Element) -> VulnerabilitySignature:
        """Create VulnerabilitySignature from XML element."""
        threat_id = e.get("name")
        threat_name = strip_empty(e.findtext("threatname"))

        vendor_id = []
        for vendor in e.findall(".//vendor/member"):
            vendor_id.append(vendor.text)

        cve_id = []
        for cve in e.findall(".//cve/member"):
            cve_id.append(cve.text)

        category = strip_empty(e.findtext("category"))
        severity = strip_empty(e.findtext("severity"))

        min_version = None
        max_version = None
        engine_version = e.find(".//engine-version")
        if engine_version is not None:
            min_version = engine_version.get("min")
            max_version = engine_version.get("max")

        default_action = strip_empty(e.findtext("default-action"))

        affected_hosts = []
        for affected_host in e.findall("./affected-host/"):
            affected_hosts.append(affected_host.tag)

        return VulnerabilitySignature(
            threat_id,
            threat_name,
            vendor_id,
            cve_id,
            category,
            severity,
            min_version,
            max_version,
            affected_hosts,
            default_action,
        )


class SecurityProfileGroup(
    namedtuple(
        "SecurityProfileGroup",
        [
            "name",
            "virus",
            "spyware",
            "vulnerability",
            "url_filtering",
            "wildfire_analysis",
        ],
    )
):
    """Class representing a security profile group."""

    @staticmethod
    def create_from_element(e: Element) -> SecurityProfileGroup:
        """Create SecurityProfileGroup from XML element."""
        name = e.get("name")

        virus = strip_empty(e.findtext(".//virus/member"))
        spyware = strip_empty(e.findtext(".//spyware/member"))
        vulnerability = strip_empty(e.findtext(".//vulnerability/member"))
        url_filtering = strip_empty(e.findtext(".//url-filtering/member"))
        wildfire_analysis = strip_empty(e.findtext(".//wildfire-analysis/member"))

        return SecurityProfileGroup(
            name, virus, spyware, vulnerability, url_filtering, wildfire_analysis
        )
