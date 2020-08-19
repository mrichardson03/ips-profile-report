import xmltodict

from panos_util import VulnerabilitySignature

STANDARD = """
<entry name="31673" p="yes">
    <threatname>SCADA ICCP Unauthorized MMS Write Request Attempt</threatname>
    <vendor xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <member>1111404</member>
    </vendor>
    <category>info-leak</category>
    <severity>low</severity>
    <engine-version min="5.0"/>
    <affected-host>
        <server>yes</server>
    </affected-host>
    <default-action>alert</default-action>
</entry>
"""

NO_AFFECTED_HOST = """
<entry name="57212" p="yes">
    <threatname>
        Advantech WebAccess SCADA bwrunmie.exe Policy Bypass Vulnerability
    </threatname>
    <cve xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <member>CVE-2019-13552</member>
    </cve>
    <category>code-execution</category>
    <severity>high</severity>
    <engine-version min="7.1"/>
    <affected-host/>
    <default-action>alert</default-action>
</entry>
"""

NO_DEFAULT_ACTION = """
<entry name="36944" p="yes">
    <threatname>
        Galil RIO 47100 PLC Denial of Service Vulnerability
    </threatname>
    <cve xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <member>CVE-2013-0699</member>
    </cve>
    <category>dos</category>
    <severity>high</severity>
    <engine-version min="4.0"/>
    <affected-host>
        <server>yes</server>
    </affected-host>
</entry>
"""

MULTI_CVE = """
<entry name="40834" p="yes">
    <threatname>
        Quest NetVault Backup Multipart Request Part Header Stack Buffer Overflow Vulnerability
    </threatname>
    <cve xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <member>CVE-2017-17652</member>
        <member>CVE-2017-17412</member>
        <member>CVE-2018-1163</member>
        <member>CVE-2018-1162</member>
        <member>CVE-2017-17419</member>
        <member>CVE-2017-17420</member>
    </cve>
    <category>overflow</category>
    <severity>critical</severity>
    <engine-version min="6.1"/>
    <affected-host>
        <server>yes</server>
    </affected-host>
    <default-action>reset-server</default-action>
</entry>
"""


def test_standard_sig():
    xmldict = xmltodict.parse(STANDARD)
    sig = VulnerabilitySignature.create_from_xmldict(xmldict)

    assert sig.name == "SCADA ICCP Unauthorized MMS Write Request Attempt"
    assert sig.threat_id == "31673"


def test_no_affected_host():
    xmldict = xmltodict.parse(NO_AFFECTED_HOST)
    sig = VulnerabilitySignature.create_from_xmldict(xmldict)

    assert (
        sig.name == "Advantech WebAccess SCADA bwrunmie.exe Policy Bypass Vulnerability"
    )
    assert sig.threat_id == "57212"
    assert sig.affected_host is None


def test_no_default_action():
    xmldict = xmltodict.parse(NO_DEFAULT_ACTION)
    sig = VulnerabilitySignature.create_from_xmldict(xmldict)

    assert sig.name == "Galil RIO 47100 PLC Denial of Service Vulnerability"
    assert sig.threat_id == "36944"
    assert sig.default_action is None


def test_multi_cve():
    xmldict = xmltodict.parse(MULTI_CVE)
    sig = VulnerabilitySignature.create_from_xmldict(xmldict)

    assert (
        sig.name
        == "Quest NetVault Backup Multipart Request Part Header Stack Buffer Overflow Vulnerability"
    )
    assert sig.threat_id == "40834"
    assert sig.cve_id == [
        "CVE-2017-17652",
        "CVE-2017-17412",
        "CVE-2018-1163",
        "CVE-2018-1162",
        "CVE-2017-17419",
        "CVE-2017-17420",
    ]
