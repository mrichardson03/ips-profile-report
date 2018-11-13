#!/usr/bin/env python

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import argparse
import csv
import tarfile
import xml.etree.ElementTree

from collections import Counter

import xmltodict


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
        for rule in self.rules:
            if not rule.alert_only():
                return False
        return True

    @staticmethod
    def create_from_xmldict(xmldict):
        name = xmldict['entry']['@name']
        rules = list()
        for rule in xmldict['entry']['rules']['entry']:
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

    def __init__(self, name, vendor_id, cve, severity, action, threat_name, host, category, packet_capture):
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
        if 'critical' in self.severity and self.action in ['drop', 'reset-both']:
            return True
        else:
            return False

    def blocks_high(self):
        if 'high' in self.severity and self.action in ['drop', 'reset-both']:
            return True
        else:
            return False

    def blocks_medium(self):
        if 'medium' in self.severity and self.action in ['drop', 'reset-both']:
            return True
        else:
            return False

    def alert_only(self):
        if self.action == 'alert':
            return True
        else:
            return False

    @staticmethod
    def create_from_xmldict(xmldict):
        name = xmldict['@name']
        vendor_id = xmldict['vendor-id'].values()
        cve = xmldict['cve'].values()
        if isinstance(xmldict['severity']['member'], str):
            severity = xmldict['severity'].values()
        else:
            severity = xmldict['severity']['member']
        action = list(xmldict['action'].keys())[0]
        threat_name = xmldict['threat-name']
        host = xmldict['host']
        category = xmldict['category']
        packet_capture = xmldict['packet-capture']
        return VulnerabilityProfileRule(name, vendor_id, cve, severity, action, threat_name, host, category, packet_capture)


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
        name = xmldict['entry']['@name']
        virus = None
        if 'virus' in xmldict['entry']:
            virus = list(xmldict['entry']['virus'].values())[0]
        spyware = None
        if 'spyware' in xmldict['entry']:
            spyware = list(xmldict['entry']['spyware'].values())[0]
        vulnerability = None
        if 'vulnerability' in xmldict['entry']:
            vulnerability = list(xmldict['entry']['vulnerability'].values())[0]
        wildfire_analysis = None
        if 'wildfire_analysis' in xmldict['entry']:
            wildfire_analysis = list(xmldict['entry']['wildfire-analysis'].values())[0]
        return SecurityProfileGroup(name, virus, spyware, vulnerability, wildfire_analysis)


class SecurityRule:

    def __init__(self, name, action, disabled, security_profile_group, vulnerability_profile):
        self._name = name
        self._action = action
        self._disabled = disabled
        self._security_profile_group = security_profile_group
        self._vulnerability_profile = vulnerability_profile

    @property
    def name(self):
        return self._name

    @property
    def action(self):
        return self._action

    @property
    def disabled(self):
        return self._disabled

    @property
    def security_profile_group(self):
        return self._security_profile_group

    @security_profile_group.setter
    def security_profile_group(self, value):
        self._security_profile_group = value

    @property
    def vulnerability_profile(self):
        return self._vulnerability_profile

    @vulnerability_profile.setter
    def vulnerability_profile(self, value):
        self._vulnerability_profile = value

    @staticmethod
    def create_from_xmldict(xmldict):
        name = xmldict['entry']['@name']
        action = xmldict['entry']['action']
        if 'disabled' in xmldict['entry'] and xmldict['entry']['disabled'] == 'yes':
            disabled = True
        else:
            disabled = False

        security_profile_group = None
        vulnerability_profile = None

        if 'profile-setting' in xmldict['entry']:
            if 'group' in xmldict['entry']['profile-setting']:
                if xmldict['entry']['profile-setting']['group'] is not None:
                    security_profile_group = list(xmldict['entry']['profile-setting']['group'].values())[0]
            elif 'profiles' in xmldict['entry']['profile-setting']:
                if xmldict['entry']['profile-setting']['profiles'] is not None:
                    if 'vulnerability' in xmldict['entry']['profile-setting']['profiles']:
                        vulnerability_profile = list(xmldict['entry']['profile-setting']['profiles']['vulnerability'].values())[0]

        return SecurityRule(name, action, disabled, security_profile_group, vulnerability_profile)


def resolve_vuln_profile(rule, device_group_name, profile_group_dict, vuln_profile_dict):

    vp_name = None

    # If a rule has a security profile group defined...
    if rule.security_profile_group:

        # Look in the profile group dict to see if it has anything specific
        # for this device group.
        if device_group_name in profile_group_dict:

            # If we have a security profile group that matches the one on the
            # rule, grab the vulnerability profile name from it.
            if rule.security_profile_group in profile_group_dict[device_group_name]:
                vp_name = profile_group_dict[device_group_name][rule.security_profile_group].vulnerability

        # If there wasn't anything defined for the device group, check the
        # shared objects.
        if rule.security_profile_group in profile_group_dict['shared']:
            vp_name = profile_group_dict['shared'][rule.security_profile_group].vulnerability

    # If rule has a vulnerability profile defined, or if we found a
    # vulnerability profile in a security profile group above...
    if rule.vulnerability_profile or vp_name is not None:

        # If vp_name is still None, we're just looking for the vulnerability
        # profile on the rule itself.
        if vp_name is None:
            vp_name = rule.vulnerability_profile

        # Like before, look in the vuln profile dict to see if we have anything
        # specific for this device group.
        if device_group_name in vuln_profile_dict:

            # If we have a vulnerability profile that matches the one on the
            # rule, return it.
            if vp_name in vuln_profile_dict[device_group_name]:
                return vuln_profile_dict[device_group_name][vp_name]

        # If there wasn't anything defined for the device group, check the
        # shared objects.
        if vp_name in vuln_profile_dict['shared']:
            return vuln_profile_dict['shared'][vp_name]

        # Handle the default vulnerability profiles 'strict' and 'default'
        # specially since they don't actually exist in the config.
        if vp_name == 'strict':
            return StrictVulnerabilityProfile()
        elif vp_name == 'default':
            return DefaultVulnerabilityProfile()

    return None


def parse_xml(xml_doc):
    tree = xml.etree.ElementTree.fromstring(xml_doc)

    vuln_profiles = dict()
    profile_groups = dict()

    rule_counts = dict()

    # Shared vulnerability profiles.
    for vuln_profile in tree.findall('./shared/profiles/vulnerability/entry'):
        raw_xml = xml.etree.ElementTree.tostring(vuln_profile)
        xmldict = xmltodict.parse(raw_xml)
        vp = VulnerabilityProfile.create_from_xmldict(xmldict)

        if 'shared' not in vuln_profiles:
            vuln_profiles['shared'] = dict()
        vuln_profiles['shared'][vp.name] = vp

    # Shared security profile groups.
    for profile_group in tree.findall('./shared/profile-group/entry'):
        raw_xml = xml.etree.ElementTree.tostring(profile_group)
        xmldict = xmltodict.parse(raw_xml)
        spg = SecurityProfileGroup.create_from_xmldict(xmldict)

        if 'shared' not in profile_groups:
            profile_groups['shared'] = dict()
        profile_groups['shared'][spg.name] = spg

    # Loop through all device groups in the config.
    for device_group in tree.findall('./devices/entry/device-group/entry'):
        dg_name = device_group.attrib['name']

        # Device group specific vulnerability profiles.
        for vuln_profile in device_group.findall('./profiles/vulnerability/entry'):
            raw_xml = xml.etree.ElementTree.tostring(vuln_profile)
            xmldict = xmltodict.parse(raw_xml)
            vp = VulnerabilityProfile.create_from_xmldict(xmldict)

            if dg_name not in vuln_profiles:
                vuln_profiles[dg_name] = dict()
            vuln_profiles[dg_name][vp.name] = vp

        # Device group specific security profiles.
        for profile_group in device_group.findall('./profile-group/entry'):
            raw_xml = xml.etree.ElementTree.tostring(profile_group)
            xmldict = xmltodict.parse(raw_xml)
            spg = SecurityProfileGroup.create_from_xmldict(xmldict)

            if dg_name not in profile_groups:
                profile_groups[dg_name] = dict()

            profile_groups[dg_name][spg.name] = spg

        if dg_name not in rule_counts:
            rule_counts[dg_name] = Counter()

        # Loop through all pre-rules in the config.
        for rule in device_group.findall('./pre-rulebase/security/rules/entry'):
            raw_xml = xml.etree.ElementTree.tostring(rule)
            xmldict = xmltodict.parse(raw_xml)
            r = SecurityRule.create_from_xmldict(xmldict)

            rule_counts[dg_name]['total_rules'] += 1

            if r.action == 'allow' and not r.disabled:
                rule_counts[dg_name]['allow'] += 1

                vp = resolve_vuln_profile(r, dg_name, profile_groups, vuln_profiles)

                if isinstance(vp, VulnerabilityProfile):
                    if vp.alert_only():
                        rule_counts[dg_name]['alert_only'] += 1
                    else:
                        if vp.blocks_criticals():
                            rule_counts[dg_name]['blocks_criticals'] += 1
                        if vp.blocks_high():
                            rule_counts[dg_name]['blocks_high'] += 1
                        if vp.blocks_medium():
                            rule_counts[dg_name]['blocks_medium'] += 1

                elif vp is None:
                    if r.security_profile_group is not None or r.vulnerability_profile is not None:
                        print("PROBLEM")
                        print("security_profile_group = {}".format(r.security_profile_group))
                        print("vulnerability_profile = {}".format(r.vulnerability_profile))

            elif r.disabled:
                rule_counts[dg_name]['disabled'] += 1

    return rule_counts


def csv_output(output_file, rule_counts):
    with open(output_file, 'w') as csv_file:
        writer = csv.writer(csv_file)

        writer.writerow([
            'Device Group Name', 'Total Rules', 'Allow Rules',
            'Disabled Rules', 'Blocks Criticals', 'Blocks High',
            'Blocks Medium', 'Alert Only'
        ])

        for dg in sorted(rule_counts):
            c = rule_counts[dg]

            if c['total_rules'] > 0:
                writer.writerow([
                    dg, c['total_rules'], c['allow'], c['disabled'],
                    c['blocks_criticals'], c['blocks_high'], c['blocks_medium'],
                    c['alert_only']
                ])


def main():
    parser = argparse.ArgumentParser(description='''Generate IPS usage report from Panorama tech support file.''')

    required = parser.add_argument_group()
    required.add_argument('ts_file', help='Tech Support file for input')
    required.add_argument('output_file', help='Output file for report')

    args = parser.parse_args()

    ts_file = tarfile.open(args.ts_file, mode='r:gz')
    xml_file = ts_file.extractfile('./opt/pancfg/mgmt/saved-configs/running-config.xml')
    xml_doc = xml_file.read()

    rule_counts = parse_xml(xml_doc)
    csv_output(args.output_file, rule_counts)


if __name__ == '__main__':
    main()
