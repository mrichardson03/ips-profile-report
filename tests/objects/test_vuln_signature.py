import xmltodict

from panos_util.objects import VulnerabilitySignature

EMPTY = """
<entry name="1"/>
"""

EMPTY_CHILD = """
<entry name="2">
    <threatname/>
    <vendor/>
    <cve/>
    <category/>
    <severity/>
    <engine-version/>
    <affected-host/>
    <default-action/>
</entry>
"""

SINGLE_CHILD = """
<entry name="Single-Child">
    <vendor>
        <member>one</member>
    </vendor>
    <cve>
        <member>one</member>
    </cve>
    <affected-host>
        <server>yes</server>
    </affected-host>
</entry>
"""

MULTI_CHILD = """
<entry name="Multi-Child">
    <vendor>
        <member>one</member>
        <member>two</member>
    </vendor>
    <cve>
        <member>one</member>
        <member>two</member>
    </cve>
    <engine-version min="1.0" max="2.0"/>
    <affected-host>
        <server>yes</server>
        <client>yes</client>
    </affected-host>
</entry>
"""

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


def test_empty():
    xmldict = xmltodict.parse(EMPTY)
    sig = VulnerabilitySignature.create_from_xmldict(xmldict)

    assert sig.name is None
    assert sig.vendor_id is None
    assert sig.cve_id == []
    assert sig.category is None
    assert sig.severity is None
    assert sig.min_version is None
    assert sig.max_version is None
    assert sig.affected_host is None
    assert sig.default_action is None


def test_empty_child():
    xmldict = xmltodict.parse(EMPTY_CHILD)
    sig = VulnerabilitySignature.create_from_xmldict(xmldict)

    assert sig.name is None
    assert sig.vendor_id is None
    assert sig.cve_id == []
    assert sig.category is None
    assert sig.severity is None
    assert sig.min_version is None
    assert sig.max_version is None
    assert sig.affected_host is None
    assert sig.default_action is None


def test_single_child():
    xmldict = xmltodict.parse(SINGLE_CHILD)
    sig = VulnerabilitySignature.create_from_xmldict(xmldict)

    assert sig.vendor_id == ["one"]
    assert sig.cve_id == ["one"]
    assert sig.affected_host == ["server"]


def test_multi_child():
    xmldict = xmltodict.parse(MULTI_CHILD)
    sig = VulnerabilitySignature.create_from_xmldict(xmldict)

    assert sig.vendor_id == ["one", "two"]
    assert sig.cve_id == ["one", "two"]
    assert sig.affected_host == ["server", "client"]


def test_standard_sig():
    xmldict = xmltodict.parse(STANDARD)
    sig = VulnerabilitySignature.create_from_xmldict(xmldict)

    assert sig.name == "SCADA ICCP Unauthorized MMS Write Request Attempt"
    assert sig.threat_id == "31673"
    assert sig.category == "info-leak"
    assert sig.severity == "low"
    assert sig.min_version == "5.0"
    assert sig.max_version is None
    assert sig.affected_host == ["server"]
    assert sig.default_action == "alert"
