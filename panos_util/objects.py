from __future__ import annotations

from collections import namedtuple
from xml.etree.ElementTree import Element

from . import strip_empty


class VulnerabilityProfile:
    def __init__(self, name, rules):
        self.name = name
        self.rules = rules

    def blocks_criticals(self):
        for rule in self.rules:
            if rule.blocks_criticals():
                return True
        return False

    def blocks_high(self):
        for rule in self.rules:
            if rule.blocks_high():
                return True
        return False

    def blocks_medium(self):
        for rule in self.rules:
            if rule.blocks_medium():
                return True
        return False

    def alert_only(self):
        if len(self.rules) > 0:
            for rule in self.rules:
                if not rule.alert_only():
                    return False
            return True
        else:
            return False

    @staticmethod
    def create_from_element(e: Element) -> VulnerabilityProfile:
        """ Create VulnerabilityProfile from XML element. """
        name = e.get("name")

        rules = []
        for rule in e.findall(".//rules/entry"):
            r = VulnerabilityProfileRule.create_from_element(rule)
            rules.append(r)

        return VulnerabilityProfile(name, rules)


class DefaultVulnerabilityProfile(VulnerabilityProfile):
    def __init__(self):
        pass

    @property
    def name(self):
        return "default"

    def blocks_criticals(self):
        return False

    def blocks_high(self):
        return False

    def blocks_medium(self):
        return False

    def alert_only(self):
        return False


class StrictVulnerabilityProfile(VulnerabilityProfile):
    def __init__(self):
        pass

    @property
    def name(self):
        return "strict"

    def blocks_criticals(self):
        return True

    def blocks_high(self):
        return True

    def blocks_medium(self):
        return True

    def alert_only(self):
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
    def blocks_criticals(self):
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

    def blocks_high(self):
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

    def blocks_medium(self):
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

    def alert_only(self):
        if self.action == "alert":
            return True
        else:
            return False

    @staticmethod
    def create_from_element(e: Element) -> VulnerabilityProfileRule:
        """ Create VulnerabilityProfileRule from XML element. """
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
    @staticmethod
    def create_from_element(e: Element) -> VulnerabilitySignature:
        """ Create VulnerabilitySignature from XML element. """
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
    @staticmethod
    def create_from_element(e: Element) -> SecurityProfileGroup:
        """ Create SecurityProfileGroup from XML element. """
        name = e.get("name")

        virus = strip_empty(e.findtext(".//virus/member"))
        spyware = strip_empty(e.findtext(".//spyware/member"))
        vulnerability = strip_empty(e.findtext(".//vulnerability/member"))
        url_filtering = strip_empty(e.findtext(".//url-filtering/member"))
        wildfire_analysis = strip_empty(e.findtext(".//wildfire-analysis/member"))

        return SecurityProfileGroup(
            name, virus, spyware, vulnerability, url_filtering, wildfire_analysis
        )
