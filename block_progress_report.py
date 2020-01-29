#!/usr/bin/env python

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import argparse
import tarfile
import xml.etree.ElementTree

from collections import Counter

import xmltodict
import xlsxwriter
from xlsxwriter.utility import xl_rowcol_to_cell

import json

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
        print(json.dumps(xmldict, indent=4))
        name = xmldict['entry']['@name']
        rules = list()

        if 'rules' in xmldict['entry']:

            if isinstance(xmldict['entry']['rules']['entry'], list):
                for rule in xmldict['entry']['rules']['entry']:
                    new_rule = VulnerabilityProfileRule.create_from_xmldict(rule)
                    rules.append(new_rule)
            else:
                rule = xmldict['entry']['rules']['entry']
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
        if 'critical' in self.severity and self.action in [
            'block-ip', 'drop', 'reset-both', 'reset-client', 'reset-server'
        ]:
            return True
        else:
            return False

    def blocks_high(self):
        if 'high' in self.severity and self.action in [
            'block-ip', 'drop', 'reset-both', 'reset-client', 'reset-server'
        ]:
            return True
        else:
            return False

    def blocks_medium(self):
        if 'medium' in self.severity and self.action in [
            'block-ip', 'drop', 'reset-both', 'reset-client', 'reset-server'
        ]:
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


def excel_output(output_file, rule_counts):
    workbook = xlsxwriter.Workbook(output_file)
    worksheet = workbook.add_worksheet()

    column_headers = [
        'Device Group Name', 'Total Rules', 'Allow Rules', 'Disabled Rules',
        'Blocks Criticals', 'Critical %', 'Blocks High', 'High %',
        'Blocks Medium', 'Medium %', 'Alert Only', 'Alert %',
        '', 'Critical High Medium % per Device Group'
    ]

    header_format = workbook.add_format(
        {
            'bold': True, 'font_color': '#455569', 'bottom': 2,
            'border_color': '#9DC3E4'
        }
    )

    centered_header_format = workbook.add_format(
        {
            'bold': True, 'font_color': '#455569', 'bottom': 2,
            'border_color': '#9DC3E4', 'align': 'center'
        }
    )

    footer_format = workbook.add_format(
        {
            'bold': True, 'font_color': '#455569', 'top': 1, 'bottom': 6,
            'border_color': '#9DC3E4'
        }
    )

    centered_footer_format = workbook.add_format(
        {
            'bold': True, 'font_color': '#455569', 'top': 1, 'bottom': 6,
            'border_color': '#9DC3E4', 'align': 'center'
        }
    )

    centered_pct_footer_format = workbook.add_format(
        {
            'bold': True, 'font_color': '#455569', 'top': 1, 'bottom': 6,
            'border_color': '#9DC3E4', 'align': 'center', 'num_format': '0.00%'
        }
    )

    center_format = workbook.add_format(
        {'align': 'center'}
    )

    center_pct_format = workbook.add_format(
        {'align': 'center', 'num_format': '0.00%'}
    )

    # Page Setup
    worksheet.set_landscape()
    worksheet.fit_to_pages(1, 0)

    # Column width
    worksheet.set_column('A:A', 30)
    worksheet.set_column('B:M', 15)
    worksheet.set_column('N:N', 40)

    # Column headers
    worksheet.write(0, 0, column_headers[0], header_format)

    row = 0
    col = 1

    for header in column_headers[1:]:
        worksheet.write(row, col, header, centered_header_format)
        col += 1

    row = 1
    col = 0

    for dg in sorted(rule_counts):
        c = rule_counts[dg]

        if c['allow'] > 0:
            # Device Group Name
            worksheet.write(row, 0, dg)

            # Total Rules
            worksheet.write(row, 1, c['total_rules'], center_format)

            # Allow Rules
            worksheet.write(row, 2, c['allow'], center_format)

            # Disabled Rules
            worksheet.write(row, 3, c['disabled'], center_format)

            # Blocks Criticals
            worksheet.write(row, 4, c['blocks_criticals'], center_format)

            # Blocks Criticals %
            blocks_criticals_pct = (
                f"={xl_rowcol_to_cell(row, 4)}/{xl_rowcol_to_cell(row, 2)}"
            )
            worksheet.write(row, 5, blocks_criticals_pct, center_pct_format)

            # Blocks High
            worksheet.write(row, 6, c['blocks_high'], center_format)

            # Blocks High %
            blocks_high_pct = (
                f"={xl_rowcol_to_cell(row, 6)}/{xl_rowcol_to_cell(row, 2)}"
            )
            worksheet.write(row, 7, blocks_high_pct, center_pct_format)

            # Blocks Medium
            worksheet.write(row, 8, c['blocks_medium'], center_format)

            # Blocks Medium %
            blocks_medium_pct = (
                f"={xl_rowcol_to_cell(row, 8)}/{xl_rowcol_to_cell(row, 2)}"
            )
            worksheet.write(row, 9, blocks_medium_pct, center_pct_format)

            # Alert Only
            worksheet.write(row, 10, c['alert_only'], center_format)

            # Alert Only %
            alert_only_pct = (
                f"={xl_rowcol_to_cell(row, 10)}/{xl_rowcol_to_cell(row, 2)}"
            )
            worksheet.write(row, 11, alert_only_pct, center_pct_format)

            # Critical High Medium %
            critical_high_medium_pct = (
                f"=({xl_rowcol_to_cell(row, 4)}+{xl_rowcol_to_cell(row, 6)}+"
                f"{xl_rowcol_to_cell(row, 8)})/({xl_rowcol_to_cell(row, 2)}*3)"
            )
            worksheet.write(row, 13, critical_high_medium_pct, center_pct_format)

            row += 1

    # Skip a row for totals
    row += 1

    worksheet.write(row, 0, 'Overall Totals', footer_format)

    # Total Rules
    total_rules = (
        f"=SUM({xl_rowcol_to_cell(1, 1)}:{xl_rowcol_to_cell(row - 2, 1)})"
    )
    worksheet.write(row, 1, total_rules, centered_footer_format)

    # Total Allow
    total_allow = (
        f"=SUM({xl_rowcol_to_cell(1, 2)}:{xl_rowcol_to_cell(row - 2, 2)})"
    )
    worksheet.write(row, 2, total_allow, centered_footer_format)

    # Total Disabled
    total_disabled = (
        f"=SUM({xl_rowcol_to_cell(1, 3)}:{xl_rowcol_to_cell(row - 2, 3)})"
    )
    worksheet.write(row, 3, total_disabled, centered_footer_format)

    # Total Blocks Criticals
    total_blocks_criticals = (
        f"=SUM({xl_rowcol_to_cell(1, 4)}:{xl_rowcol_to_cell(row - 2, 4)})"
    )
    worksheet.write(row, 4, total_blocks_criticals, centered_footer_format)

    # Total Blocks Criticals %
    total_blocks_criticals_pct = (
        f"={xl_rowcol_to_cell(row, 4)}/{xl_rowcol_to_cell(row, 2)}"
    )
    worksheet.write(row, 5, total_blocks_criticals_pct, centered_pct_footer_format)

    # Total Blocks High
    total_blocks_high = (
        f"=SUM({xl_rowcol_to_cell(1, 6)}:{xl_rowcol_to_cell(row - 2, 6)})"
    )
    worksheet.write(row, 6, total_blocks_high, centered_footer_format)

    # Total Blocks High %
    total_blocks_high_pct = (
        f"={xl_rowcol_to_cell(row, 6)}/{xl_rowcol_to_cell(row, 2)}"
    )
    worksheet.write(row, 7, total_blocks_high_pct, centered_pct_footer_format)

    # Total Blocks Medium
    total_blocks_medium = (
        f"=SUM({xl_rowcol_to_cell(1, 8)}:{xl_rowcol_to_cell(row - 2, 8)})"
    )
    worksheet.write(row, 8, total_blocks_medium, centered_footer_format)

    # Total Blocks Medium %
    total_blocks_medium_pct = (
        f"={xl_rowcol_to_cell(row, 8)}/{xl_rowcol_to_cell(row, 2)}"
    )
    worksheet.write(row, 9, total_blocks_medium_pct, centered_pct_footer_format)

    # Total Alert Only
    total_alert_only = (
        f"=SUM({xl_rowcol_to_cell(1, 10)}:{xl_rowcol_to_cell(row - 2, 10)})"
    )
    worksheet.write(row, 10, total_alert_only, centered_footer_format)

    # Total Alert Only %
    total_alert_only_pct = (
        f"={xl_rowcol_to_cell(row, 10)}/{xl_rowcol_to_cell(row, 2)}"
    )
    worksheet.write(row, 11, total_alert_only_pct, centered_pct_footer_format)

    worksheet.write(row, 12, '', footer_format)

    # Total Critical High Medium %
    total_critical_high_medium_pct = (
        f"=({xl_rowcol_to_cell(row, 4)}+{xl_rowcol_to_cell(row, 6)}+"
        f"{xl_rowcol_to_cell(row, 8)})/({xl_rowcol_to_cell(row, 2)}*3)"
    )
    worksheet.write(
        row, 13, total_critical_high_medium_pct, centered_pct_footer_format
    )

    # Column Conditional Formatting
    critical_pct_cond_cells = (
        f"{xl_rowcol_to_cell(1, 5)}:{xl_rowcol_to_cell(row, 5)}"
    )
    worksheet.conditional_format(critical_pct_cond_cells, {'type': '3_color_scale'})

    high_pct_cond_cells = (
        f"{xl_rowcol_to_cell(1, 7)}:{xl_rowcol_to_cell(row, 7)}"
    )
    worksheet.conditional_format(high_pct_cond_cells, {'type': '3_color_scale'})

    medium_pct_cond_cells = (
        f"{xl_rowcol_to_cell(1, 9)}:{xl_rowcol_to_cell(row, 9)}"
    )
    worksheet.conditional_format(medium_pct_cond_cells, {'type': '3_color_scale'})

    alert_only_pct_cond_cells = (
        f"{xl_rowcol_to_cell(1, 11)}:{xl_rowcol_to_cell(row, 11)}"
    )
    worksheet.conditional_format(
        alert_only_pct_cond_cells,
        {'type': '3_color_scale', 'min_color': '#6ABC7D', 'max_color': '#f46B6E'}
    )

    critical_high_medium_pct_cond_cells = (
        f"{xl_rowcol_to_cell(1, 13)}:{xl_rowcol_to_cell(row, 13)}"
    )
    worksheet.conditional_format(
        critical_high_medium_pct_cond_cells,
        {'type': '3_color_scale'}
    )

    workbook.close()


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
    excel_output(args.output_file, rule_counts)


if __name__ == '__main__':
    main()
