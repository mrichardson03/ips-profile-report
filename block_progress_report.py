#!/usr/bin/env python3

from __future__ import absolute_import, division, print_function

import argparse
import tarfile
import xml.etree.ElementTree
from collections import Counter

import xlsxwriter
import xmltodict
from xlsxwriter.utility import xl_rowcol_to_cell

from panos_util.objects import (
    DefaultVulnerabilityProfile,
    SecurityProfileGroup,
    StrictVulnerabilityProfile,
    VulnerabilityProfile,
)
from panos_util.policies import SecurityRule

__metaclass__ = type


def resolve_vuln_profile(
    rule, device_group_name, profile_group_dict, vuln_profile_dict
):
    vp_name = None

    # If a rule has a security profile group defined...
    if rule.security_profile_group:

        # Look in the profile group dict to see if it has anything specific
        # for this device group.
        if device_group_name in profile_group_dict:

            # If we have a security profile group that matches the one on the
            # rule, grab the vulnerability profile name from it.
            if rule.security_profile_group in profile_group_dict[device_group_name]:
                vp_name = profile_group_dict[device_group_name][
                    rule.security_profile_group
                ].vulnerability

        # If there wasn't anything defined for the device group, check the
        # shared objects.
        if rule.security_profile_group in profile_group_dict["shared"]:
            vp_name = profile_group_dict["shared"][
                rule.security_profile_group
            ].vulnerability

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
        if vp_name in vuln_profile_dict["shared"]:
            return vuln_profile_dict["shared"][vp_name]

        # Handle the default vulnerability profiles 'strict' and 'default'
        # specially since they don't actually exist in the config.
        if vp_name == "strict":
            return StrictVulnerabilityProfile()
        elif vp_name == "default":
            return DefaultVulnerabilityProfile()

    return None


def parse_xml(xml_doc):
    tree = xml.etree.ElementTree.fromstring(xml_doc)

    vuln_profiles = dict()
    profile_groups = dict()

    rule_counts = dict()

    # Shared vulnerability profiles.
    for vuln_profile in tree.findall("./shared/profiles/vulnerability/entry"):
        raw_xml = xml.etree.ElementTree.tostring(vuln_profile)
        xmldict = xmltodict.parse(raw_xml)
        vp = VulnerabilityProfile.create_from_xmldict(xmldict)

        if "shared" not in vuln_profiles:
            vuln_profiles["shared"] = dict()
        vuln_profiles["shared"][vp.name] = vp

    # Shared security profile groups.
    for profile_group in tree.findall("./shared/profile-group/entry"):
        raw_xml = xml.etree.ElementTree.tostring(profile_group)
        xmldict = xmltodict.parse(raw_xml)
        spg = SecurityProfileGroup.create_from_xmldict(xmldict)

        if "shared" not in profile_groups:
            profile_groups["shared"] = dict()
        profile_groups["shared"][spg.name] = spg

    # Loop through all device groups in the config.
    for device_group in tree.findall("./devices/entry/device-group/entry"):
        dg_name = device_group.attrib["name"]

        # Device group specific vulnerability profiles.
        for vuln_profile in device_group.findall("./profiles/vulnerability/entry"):
            raw_xml = xml.etree.ElementTree.tostring(vuln_profile)
            xmldict = xmltodict.parse(raw_xml)
            vp = VulnerabilityProfile.create_from_xmldict(xmldict)

            if dg_name not in vuln_profiles:
                vuln_profiles[dg_name] = dict()
            vuln_profiles[dg_name][vp.name] = vp

        # Device group specific security profiles.
        for profile_group in device_group.findall("./profile-group/entry"):
            raw_xml = xml.etree.ElementTree.tostring(profile_group)
            xmldict = xmltodict.parse(raw_xml)
            spg = SecurityProfileGroup.create_from_xmldict(xmldict)

            if dg_name not in profile_groups:
                profile_groups[dg_name] = dict()

            profile_groups[dg_name][spg.name] = spg

        if dg_name not in rule_counts:
            rule_counts[dg_name] = Counter()

        # Loop through all pre-rules in the config.
        for rule in device_group.findall("./pre-rulebase/security/rules/entry"):
            raw_xml = xml.etree.ElementTree.tostring(rule)
            xmldict = xmltodict.parse(raw_xml)
            r = SecurityRule.create_from_xmldict(xmldict)

            rule_counts[dg_name]["total_rules"] += 1

            if r.action == "allow" and not r.disabled:
                rule_counts[dg_name]["allow"] += 1

                vp = resolve_vuln_profile(r, dg_name, profile_groups, vuln_profiles)

                if isinstance(vp, VulnerabilityProfile):
                    if vp.alert_only():
                        rule_counts[dg_name]["alert_only"] += 1
                    else:
                        if vp.blocks_criticals():
                            rule_counts[dg_name]["blocks_criticals"] += 1
                        if vp.blocks_high():
                            rule_counts[dg_name]["blocks_high"] += 1
                        if vp.blocks_medium():
                            rule_counts[dg_name]["blocks_medium"] += 1

                elif vp is None:
                    if (
                        r.security_profile_group is not None
                        or r.vulnerability_profile is not None
                    ):
                        print("PROBLEM")
                        print(
                            "security_profile_group = {}".format(
                                r.security_profile_group
                            )
                        )
                        print(
                            "vulnerability_profile = {}".format(r.vulnerability_profile)
                        )

            elif r.disabled:
                rule_counts[dg_name]["disabled"] += 1

    return rule_counts


def excel_output(output_file, rule_counts):
    workbook = xlsxwriter.Workbook(output_file)
    worksheet = workbook.add_worksheet()

    column_headers = [
        "Device Group Name",
        "Total Rules",
        "Allow Rules",
        "Disabled Rules",
        "Blocks Criticals",
        "Critical %",
        "Blocks High",
        "High %",
        "Blocks Medium",
        "Medium %",
        "Alert Only",
        "Alert %",
        "",
        "Critical High Medium % per Device Group",
    ]

    header_format = workbook.add_format(
        {"bold": True, "font_color": "#455569", "bottom": 2, "border_color": "#9DC3E4"}
    )

    centered_header_format = workbook.add_format(
        {
            "bold": True,
            "font_color": "#455569",
            "bottom": 2,
            "border_color": "#9DC3E4",
            "align": "center",
        }
    )

    footer_format = workbook.add_format(
        {
            "bold": True,
            "font_color": "#455569",
            "top": 1,
            "bottom": 6,
            "border_color": "#9DC3E4",
        }
    )

    centered_footer_format = workbook.add_format(
        {
            "bold": True,
            "font_color": "#455569",
            "top": 1,
            "bottom": 6,
            "border_color": "#9DC3E4",
            "align": "center",
        }
    )

    centered_pct_footer_format = workbook.add_format(
        {
            "bold": True,
            "font_color": "#455569",
            "top": 1,
            "bottom": 6,
            "border_color": "#9DC3E4",
            "align": "center",
            "num_format": "0.00%",
        }
    )

    center_format = workbook.add_format({"align": "center"})

    center_pct_format = workbook.add_format({"align": "center", "num_format": "0.00%"})

    # Page Setup
    worksheet.set_landscape()
    worksheet.fit_to_pages(1, 0)

    # Column width
    worksheet.set_column("A:A", 30)
    worksheet.set_column("B:M", 15)
    worksheet.set_column("N:N", 40)

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

        if c["allow"] > 0:
            # Device Group Name
            worksheet.write(row, 0, dg)

            # Total Rules
            worksheet.write(row, 1, c["total_rules"], center_format)

            # Allow Rules
            worksheet.write(row, 2, c["allow"], center_format)

            # Disabled Rules
            worksheet.write(row, 3, c["disabled"], center_format)

            # Blocks Criticals
            worksheet.write(row, 4, c["blocks_criticals"], center_format)

            # Blocks Criticals %
            blocks_criticals_pct = (
                f"={xl_rowcol_to_cell(row, 4)}/{xl_rowcol_to_cell(row, 2)}"
            )
            worksheet.write(row, 5, blocks_criticals_pct, center_pct_format)

            # Blocks High
            worksheet.write(row, 6, c["blocks_high"], center_format)

            # Blocks High %
            blocks_high_pct = (
                f"={xl_rowcol_to_cell(row, 6)}/{xl_rowcol_to_cell(row, 2)}"
            )
            worksheet.write(row, 7, blocks_high_pct, center_pct_format)

            # Blocks Medium
            worksheet.write(row, 8, c["blocks_medium"], center_format)

            # Blocks Medium %
            blocks_medium_pct = (
                f"={xl_rowcol_to_cell(row, 8)}/{xl_rowcol_to_cell(row, 2)}"
            )
            worksheet.write(row, 9, blocks_medium_pct, center_pct_format)

            # Alert Only
            worksheet.write(row, 10, c["alert_only"], center_format)

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

    worksheet.write(row, 0, "Overall Totals", footer_format)

    # Total Rules
    total_rules = f"=SUM({xl_rowcol_to_cell(1, 1)}:{xl_rowcol_to_cell(row - 2, 1)})"
    worksheet.write(row, 1, total_rules, centered_footer_format)

    # Total Allow
    total_allow = f"=SUM({xl_rowcol_to_cell(1, 2)}:{xl_rowcol_to_cell(row - 2, 2)})"
    worksheet.write(row, 2, total_allow, centered_footer_format)

    # Total Disabled
    total_disabled = f"=SUM({xl_rowcol_to_cell(1, 3)}:{xl_rowcol_to_cell(row - 2, 3)})"
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
    total_blocks_high_pct = f"={xl_rowcol_to_cell(row, 6)}/{xl_rowcol_to_cell(row, 2)}"
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
    total_alert_only_pct = f"={xl_rowcol_to_cell(row, 10)}/{xl_rowcol_to_cell(row, 2)}"
    worksheet.write(row, 11, total_alert_only_pct, centered_pct_footer_format)

    worksheet.write(row, 12, "", footer_format)

    # Total Critical High Medium %
    total_critical_high_medium_pct = (
        f"=({xl_rowcol_to_cell(row, 4)}+{xl_rowcol_to_cell(row, 6)}+"
        f"{xl_rowcol_to_cell(row, 8)})/({xl_rowcol_to_cell(row, 2)}*3)"
    )
    worksheet.write(row, 13, total_critical_high_medium_pct, centered_pct_footer_format)

    # Column Conditional Formatting
    critical_pct_cond_cells = f"{xl_rowcol_to_cell(1, 5)}:{xl_rowcol_to_cell(row, 5)}"
    worksheet.conditional_format(critical_pct_cond_cells, {"type": "3_color_scale"})

    high_pct_cond_cells = f"{xl_rowcol_to_cell(1, 7)}:{xl_rowcol_to_cell(row, 7)}"
    worksheet.conditional_format(high_pct_cond_cells, {"type": "3_color_scale"})

    medium_pct_cond_cells = f"{xl_rowcol_to_cell(1, 9)}:{xl_rowcol_to_cell(row, 9)}"
    worksheet.conditional_format(medium_pct_cond_cells, {"type": "3_color_scale"})

    alert_only_pct_cond_cells = (
        f"{xl_rowcol_to_cell(1, 11)}:{xl_rowcol_to_cell(row, 11)}"
    )
    worksheet.conditional_format(
        alert_only_pct_cond_cells,
        {"type": "3_color_scale", "min_color": "#6ABC7D", "max_color": "#f46B6E"},
    )

    critical_high_medium_pct_cond_cells = (
        f"{xl_rowcol_to_cell(1, 13)}:{xl_rowcol_to_cell(row, 13)}"
    )
    worksheet.conditional_format(
        critical_high_medium_pct_cond_cells, {"type": "3_color_scale"}
    )

    workbook.close()


def main():
    parser = argparse.ArgumentParser(
        description="""Generate IPS usage report from Panorama tech support file."""
    )

    required = parser.add_argument_group()
    required.add_argument("ts_file", help="Tech Support file for input")
    required.add_argument("output_file", help="Output file for report")

    args = parser.parse_args()

    ts_file = tarfile.open(args.ts_file, mode="r:gz")
    xml_file = ts_file.extractfile("./opt/pancfg/mgmt/saved-configs/running-config.xml")
    xml_doc = xml_file.read()

    rule_counts = parse_xml(xml_doc)
    excel_output(args.output_file, rule_counts)


if __name__ == "__main__":
    main()
