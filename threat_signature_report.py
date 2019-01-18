#!/usr/bin/env python

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import argparse
import getpass
import sys
import xml.etree.ElementTree

from collections import namedtuple

import pan.xapi
import xmltodict
import xlsxwriter


class VulnerabilitySignature(namedtuple('VulnerabilitySignature', [
    'threat_id', 'name', 'vendor_id', 'cve_id', 'category', 'severity',
    'min_version', 'max_version', 'affected_host', 'default_action'
])):

    @staticmethod
    def create_from_xmldict(xmldict):
        threat_id = xmldict['entry']['@name']
        threat_name = xmldict['entry']['threatname']

        vendor_id = None
        if 'vendor' in xmldict['entry']:
            if isinstance(xmldict['entry']['vendor']['member'], str):
                vendor_id = [xmldict['entry']['vendor']['member']]
            else:
                vendor_id = xmldict['entry']['vendor']['member']

        cve_id = None
        if 'cve' in xmldict['entry']:
            if isinstance(xmldict['entry']['cve']['member'], str):
                cve_id = [xmldict['entry']['cve']['member']]
            else:
                cve_id = xmldict['entry']['cve']['member']

        category = xmldict['entry']['category']
        severity = xmldict['entry']['severity']

        min_version = None
        max_version = None

        if 'engine-version' in xmldict['entry']:
            if '@min' in xmldict['entry']['engine-version']:
                min_version = xmldict['entry']['engine-version']['@min']
            if '@max' in xmldict['entry']['engine-version']:
                max_version = xmldict['entry']['engine-version']['@max']

        default_action = None
        if 'default-action' in xmldict['entry']:
            default_action = xmldict['entry']['default-action']

        affected_host = None
        if 'affected-host' in xmldict['entry']:
            affected_host = list(xmldict['entry']['affected-host'].keys())

        return VulnerabilitySignature(
            threat_id, threat_name, vendor_id, cve_id, category, severity,
            min_version, max_version, affected_host, default_action
        )


def parse_xml(xml_doc):
    tree = xml.etree.ElementTree.fromstring(xml_doc)

    vulns = []

    for vuln in tree.findall('./entry'):
        raw_xml = xml.etree.ElementTree.tostring(vuln)
        xmldict = xmltodict.parse(raw_xml)
        v = VulnerabilitySignature.create_from_xmldict(xmldict)
        vulns.append(v)

    return vulns


def excel_output(output_file, vulns):
    workbook = xlsxwriter.Workbook(output_file)
    worksheet = workbook.add_worksheet()

    column_headers = [
        'Threat ID', 'Threat Name', 'Vendor ID', 'CVE ID', 'Category',
        'Severity', 'Min PAN-OS Version', 'Max PAN-OS Version',
        'Affected Host', 'Default Action'
    ]

    header_format = workbook.add_format(
        {
            'bold': True, 'font_color': '#455569', 'bottom': 2,
            'border_color': '#9DC3E4'
        }
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
            worksheet.write(row, 2, ', '.join(vuln.vendor_id))
        if vuln.cve_id:
            worksheet.write(row, 3, ', '.join(vuln.cve_id))
        worksheet.write(row, 4, vuln.category)
        worksheet.write(row, 5, vuln.severity)
        worksheet.write(row, 6, vuln.min_version)
        worksheet.write(row, 7, vuln.max_version)
        worksheet.write(row, 8, ', '.join(vuln.affected_host))
        worksheet.write(row, 9, vuln.default_action)

        row += 1

    workbook.close()


def main():
    parser = argparse.ArgumentParser(description='''Export current threat content from firewall or Panorama.''')

    parser.add_argument('-k', '--api_key', help='API key to use for connection.')

    required = parser.add_argument_group()
    required.add_argument('hostname', help='Hostname of firewall or Panorama')
    required.add_argument('output_file', help='Output file for report')

    args = parser.parse_args()

    output = None

    try:
        if args.api_key:
            xapi = pan.xapi.PanXapi(hostname=args.hostname, api_key=args.api_key)
        else:
            username = input('Username: ')
            password = getpass.getpass('Password: ')
            xapi = pan.xapi.PanXapi(
                hostname=args.hostname, username=username, password=password
            )

        xapi.op('<show><predefined><xpath>/predefined/threats/vulnerability</xpath></predefined></show>')

        output = xapi.xml_result()

    except pan.xapi.PanXapiError as e:
        print("XML-API Error: {e}".format(e))
        sys.exit(1)

    vulns = parse_xml(output)
    excel_output(args.output_file, vulns)


if __name__ == '__main__':
    main()
