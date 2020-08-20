#!/usr/bin/env python3

from __future__ import absolute_import, division, print_function

import argparse
import getpass
import sys
import xml.etree.ElementTree

import pan.xapi
import xlsxwriter
import xmltodict

from panos_util.objects import VulnerabilitySignature


def parse_xml(xml_doc):
    tree = xml.etree.ElementTree.fromstring(xml_doc)

    vulns = []

    for vuln in tree.findall("./entry"):
        raw_xml = xml.etree.ElementTree.tostring(vuln)
        xmldict = xmltodict.parse(raw_xml)
        v = VulnerabilitySignature.create_from_xmldict(xmldict)
        vulns.append(v)

    return vulns


def excel_output(output_file, vulns):
    workbook = xlsxwriter.Workbook(output_file)
    worksheet = workbook.add_worksheet()

    column_headers = [
        "Threat ID",
        "Threat Name",
        "Vendor ID",
        "CVE ID",
        "Category",
        "Severity",
        "Min PAN-OS Version",
        "Max PAN-OS Version",
        "Affected Host",
        "Default Action",
    ]

    header_format = workbook.add_format(
        {"bold": True, "font_color": "#455569", "bottom": 2, "border_color": "#9DC3E4"}
    )

    row = 0
    col = 0

    for header in column_headers:
        worksheet.write(row, col, header, header_format)
        col += 1

    row = 1
    col = 0

    for vuln in vulns:
        worksheet.write(row, 0, vuln.threat_id)
        worksheet.write(row, 1, vuln.name)
        if vuln.vendor_id:
            worksheet.write(row, 2, ", ".join(vuln.vendor_id))
        if vuln.cve_id:
            worksheet.write(row, 3, ", ".join(vuln.cve_id))
        worksheet.write(row, 4, vuln.category)
        worksheet.write(row, 5, vuln.severity)
        worksheet.write(row, 6, vuln.min_version)
        worksheet.write(row, 7, vuln.max_version)
        if vuln.affected_host:
            worksheet.write(row, 8, ", ".join(vuln.affected_host))
        worksheet.write(row, 9, vuln.default_action)

        row += 1

    workbook.close()


def main():
    parser = argparse.ArgumentParser(
        description="""Export current threat content from firewall or Panorama."""
    )

    parser.add_argument("-k", "--api_key", help="API key to use for connection.")

    required = parser.add_argument_group()
    required.add_argument("hostname", help="Hostname of firewall or Panorama")
    required.add_argument("output_file", help="Output file for report")

    args = parser.parse_args()

    output = None

    try:
        if args.api_key:
            xapi = pan.xapi.PanXapi(hostname=args.hostname, api_key=args.api_key)
        else:
            username = input("Username: ")
            password = getpass.getpass("Password: ")

            xapi = pan.xapi.PanXapi(
                hostname=args.hostname, api_username=username, api_password=password
            )

        xapi.op(
            "<show><predefined><xpath>/predefined/threats/vulnerability</xpath></predefined></show>"
        )

        output = xapi.xml_result()

    except pan.xapi.PanXapiError as e:
        print("XML-API Error: {0}".format(e))
        sys.exit(1)

    vulns = parse_xml(output)
    excel_output(args.output_file, vulns)


if __name__ == "__main__":
    main()
