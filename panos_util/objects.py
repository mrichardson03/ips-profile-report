from collections import namedtuple


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
    def create_from_xmldict(xmldict):
        name = xmldict["entry"]["@name"]
        rules = list()

        if "rules" in xmldict["entry"]:

            if isinstance(xmldict["entry"]["rules"]["entry"], list):
                for rule in xmldict["entry"]["rules"]["entry"]:
                    new_rule = VulnerabilityProfileRule.create_from_xmldict(rule)
                    rules.append(new_rule)
            else:
                rule = xmldict["entry"]["rules"]["entry"]
                new_rule = VulnerabilityProfileRule.create_from_xmldict(rule)
                rules.append(new_rule)

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


class VulnerabilityProfileRule:
    def __init__(
        self,
        name,
        vendor_id,
        cve,
        severity,
        action,
        threat_name,
        host,
        category,
        packet_capture,
    ):
        self.name = name
        self.vendor_id = vendor_id
        self.cve = cve
        self.severity = severity
        self.action = action
        self.threat_name = threat_name
        self.host = host
        self.category = category
        self.packet_capture = packet_capture

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
    def create_from_xmldict(xmldict):
        name = xmldict["@name"]

        vendor_id = None
        if "vendor-id" in xmldict and xmldict["vendor-id"] is not None:
            if isinstance(xmldict["vendor-id"]["member"], list):
                vendor_id = xmldict["vendor-id"]["member"]
            else:
                vendor_id = list(xmldict["vendor-id"].values())

        cve = None
        if "cve" in xmldict and xmldict["cve"] is not None:
            if isinstance(xmldict["cve"]["member"], list):
                cve = xmldict["cve"]["member"]
            else:
                cve = list(xmldict["cve"].values())

        severity = None
        if "severity" in xmldict and xmldict["severity"] is not None:
            if isinstance(xmldict["severity"]["member"], list):
                severity = xmldict["severity"]["member"]
            else:
                severity = list(xmldict["severity"].values())

        action = None
        if "action" in xmldict:
            if isinstance(xmldict["action"], dict):
                action = list(xmldict["action"].keys())[0]
            else:
                action = None

        threat_name = xmldict.get("threat-name", None)
        host = xmldict.get("host")
        category = xmldict.get("category")
        packet_capture = xmldict.get("packet-capture")

        return VulnerabilityProfileRule(
            name,
            vendor_id,
            cve,
            severity,
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
    def create_from_xmldict(xmldict):
        x = xmldict["entry"]

        threat_id = x.get("@name", None)
        threat_name = x.get("threatname", None)

        vendor_id = x.get("vendor", None)
        if vendor_id is not None:
            if isinstance(vendor_id.get("member", None), str):
                vendor_id = [vendor_id.get("member")]
            else:
                vendor_id = vendor_id.get("member")

        cve_id = x.get("cve", None)
        if cve_id is not None:
            if isinstance(cve_id.get("member", None), str):
                cve_id = [cve_id.get("member")]
            else:
                cve_id = cve_id.get("member")
        else:
            cve_id = []

        category = x.get("category", None)
        severity = x.get("severity", None)

        min_version = None
        max_version = None

        engine_version = x.get("engine-version", None)
        if engine_version is not None:
            min_version = engine_version.get("@min", None)
            max_version = engine_version.get("@max", None)

        default_action = x.get("default-action", None)

        affected_host = x.get("affected-host", None)
        if affected_host is not None:
            affected_host = list(affected_host.keys())

        return VulnerabilitySignature(
            threat_id,
            threat_name,
            vendor_id,
            cve_id,
            category,
            severity,
            min_version,
            max_version,
            affected_host,
            default_action,
        )


class SecurityProfileGroup:
    def __init__(self, name, virus, spyware, vulnerability, wildfire_analysis):
        self._name = name
        self._virus = virus
        self._spyware = spyware
        self._vulnerability = vulnerability
        self._wildfire_analysis = wildfire_analysis

    @property
    def name(self):
        return self._name

    @property
    def vulnerability(self):
        return self._vulnerability

    @staticmethod
    def create_from_xmldict(xmldict):
        name = xmldict["entry"]["@name"]
        virus = None
        if "virus" in xmldict["entry"]:
            virus = list(xmldict["entry"]["virus"].values())[0]
        spyware = None
        if "spyware" in xmldict["entry"]:
            spyware = list(xmldict["entry"]["spyware"].values())[0]
        vulnerability = None
        if "vulnerability" in xmldict["entry"]:
            vulnerability = list(xmldict["entry"]["vulnerability"].values())[0]
        wildfire_analysis = None
        if "wildfire_analysis" in xmldict["entry"]:
            wildfire_analysis = list(xmldict["entry"]["wildfire-analysis"].values())[0]
        return SecurityProfileGroup(
            name, virus, spyware, vulnerability, wildfire_analysis
        )
