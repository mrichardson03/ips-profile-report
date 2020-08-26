from __future__ import annotations

from collections import Counter
from xml.etree.ElementTree import Element

from .objects import (
    DefaultVulnerabilityProfile,
    SecurityProfileGroup,
    StrictVulnerabilityProfile,
    VulnerabilityProfile,
)
from .policies import SecurityRule


class DeviceGroup:
    def __init__(self, name, rules, vuln_profiles, profile_groups):
        self.name = name
        self.rules = rules
        self.vuln_profiles = {
            "strict": StrictVulnerabilityProfile(),
            "default": DefaultVulnerabilityProfile(),
        }
        self.vuln_profiles.update(vuln_profiles)
        self.profile_groups = profile_groups

        self.rule_counts = Counter()

        self._update_rule_counts()

    def _update_rule_counts(self):

        for rule in self.rules:
            self.rule_counts["total"] += 1

            if rule.disabled is False:
                self.rule_counts[rule.action] += 1

                vp = None
                if rule.vulnerability_profile is not None:
                    vp = self._lookup_profile(rule.vulnerability_profile)
                elif rule.security_profile_group is not None:
                    vp = self._lookup_profile_group(rule.security_profile_group)

                if vp is not None:
                    if vp.alert_only() is True:
                        self.rule_counts["alert_only"] += 1
                    else:
                        if vp.blocks_criticals() is True:
                            self.rule_counts["blocks_criticals"] += 1
                        if vp.blocks_high() is True:
                            self.rule_counts["blocks_high"] += 1
                        if vp.blocks_medium() is True:
                            self.rule_counts["blocks_medium"] += 1

            else:
                self.rule_counts["disabled"] += 1

    def _lookup_profile(self, name):
        return self.vuln_profiles.get(name, None)

    def _lookup_profile_group(self, name):
        pg = self.profile_groups.get(name)
        return self._lookup_profile(pg.vulnerability)

    @staticmethod
    def create_from_element(e: Element) -> DeviceGroup:
        """ Create DeviceGroup from XML element. """
        name = e.get("name")

        vuln_profiles = {}
        for vuln_profile in e.findall("./profiles/vulnerability/entry"):
            vp = VulnerabilityProfile.create_from_element(vuln_profile)
            vuln_profiles.update({vp.name: vp})

        profile_groups = {}
        for profile_group in e.findall("./profile-group/entry"):
            pg = SecurityProfileGroup.create_from_element(profile_group)
            profile_groups.update({pg.name: pg})

        rules = []
        for rule in e.findall("./pre-rulebase/security/rules/entry"):
            sr = SecurityRule.create_from_element(rule)
            rules.append(sr)

        return DeviceGroup(name, rules, vuln_profiles, profile_groups)
