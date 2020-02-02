# Palo Alto IPS Reporting Scripts

[![python-test](https://github.com/mrichardson03/ips-reports/workflows/python-test/badge.svg)](https://github.com/mrichardson03/ips-reports/actions?query=workflow%3Apython-test)

Additional IPS reports for Palo Alto Networks firewalls.

## Requirements

- Python 3.7+
- Python modules: `pan-python`, `xmltodict`, `xlsxwriter`

Required Python modules can be installed using the supplied `requirements.txt`
file:

```bash
pip install -r requirements.txt
```

## Included Scripts

### block_progress_report.py

Produces a report on the number of rules blocking critical, high, and medium
threats using a Panorama tech support file as input.

#### Usage

```bash
python block_progress_report.py <input_file> <output_file>
```

##### Required Arguments

- `input_file` - Panorama tech support file.
- `output_file` - Excel file containing report.

### threat_signature_report.py

Produces a report on all the threat signatures in the current content version
of a firewall or Panorama.

#### Usage

```bash
python threat_signature_report.py [-k | --api_key ] <hostname> <output_file>
```

##### Required Arguments

- `hostname` - Firewall or Panorama device to pull threat signatures from.
- `output_file` - Excel file containing report.

##### Optional Arguments

- `api_key` - API key to use for connection.  If this option is not specified,
the user will be prompted for the username and password to use.

## Support Policy

The code and templates in the repo are released under an as-is, best effort,
support policy. These scripts should be seen as community supported and
Palo Alto Networks will contribute our expertise as and when possible.
We do not provide technical support or help in using or troubleshooting the
components of the project through our normal support options such as
Palo Alto Networks support teams, or ASC (Authorized Support Centers)
partners and backline support options. The underlying product used
(the VM-Series firewall) by the scripts or templates are still supported,
but the support is only for the product functionality and not for help in
deploying or using the template or script itself. Unless explicitly tagged,
all projects or work posted in our GitHub repository
(at https://github.com/PaloAltoNetworks) or sites other than our official
Downloads page on https://support.paloaltonetworks.com are provided under
the best effort policy.