from __future__ import absolute_import, division, print_function

import argparse
import sys
import tarfile
import xml.etree.ElementTree as ElementTree

import xlsxwriter
from xlsxwriter.utility import xl_rowcol_to_cell

from panos_util.panorama import Panorama


def excel_output(output_file: str, p: Panorama):
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

    for dg_name in sorted(p.device_groups):
        dg = p.device_groups.get(dg_name)
        c = dg.rule_counts()

        if c["allow"] > 0:
            # Device Group Name
            worksheet.write(row, 0, dg_name)

            # Total Rules
            worksheet.write(row, 1, c["total"], center_format)

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

    try:
        ts_file = tarfile.open(args.ts_file, mode="r:gz")
        xml_file = ts_file.extractfile(
            "./opt/pancfg/mgmt/saved-configs/running-config.xml"
        )
        xml_doc = xml_file.read()
    except IOError as e:
        print("I/O Error: {0}".format(e))
        sys.exit(1)

    e = ElementTree.fromstring(xml_doc)
    p = Panorama.create_from_element(e)

    excel_output(args.output_file, p)
