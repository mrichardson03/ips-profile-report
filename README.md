# Palo Alto IPS Reporting Scripts

![CI/CD](https://github.com/mrichardson03/panos-ips-reports/workflows/CI/CD/badge.svg)

Additional IPS reports for Palo Alto Networks firewalls.

## Requirements

- Python 3.7+

## Installation

Install from PyPI using pip:

```bash
pip3 install panos-ips-reports
```

Upgrade to the latest version:

```bash
pip3 install --upgrade panos-ips-reports
```

`pip` will install the required Python modules, and add the scripts supplied by this
package to your system path.

## Included Scripts

### block_progress_report

Produces a report on the number of rules blocking critical, high, and medium
threats using a Panorama tech support file as input.

#### Usage

```bash
$ block_progress_report <input_file> <output_file>
```

##### Required Arguments

- `input_file` - Panorama tech support file.
- `output_file` - Excel file containing report.

### threat_signature_report

Produces a report on all the threat signatures in the current content version
of a firewall or Panorama.

#### Usage

```bash
threat_signature_report [-k | --api_key ] <hostname> <output_file>
```

##### Required Arguments

- `hostname` - Firewall or Panorama device to pull threat signatures from.
- `output_file` - Excel file containing report.

##### Optional Arguments

- `api_key` - API key to use for connection.  If this option is not specified,
the user will be prompted for the username and password to use.
