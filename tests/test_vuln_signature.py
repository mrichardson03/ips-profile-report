import xml.etree.ElementTree as ElementTree

from panos_util.objects import VulnerabilitySignature

EMPTY = """
<entry name="Empty"/>
"""

EMPTY_CHILD = """
<entry name="Empty-Child">
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


def test_empty():
    e = ElementTree.fromstring(EMPTY)
    sig = VulnerabilitySignature.create_from_element(e)

    assert sig.name is None
    assert sig.vendor_id == []
    assert sig.cve_id == []
    assert sig.category is None
    assert sig.severity is None
    assert sig.min_version is None
    assert sig.max_version is None
    assert sig.affected_host == []
    assert sig.default_action is None


def test_empty_child():
    e = ElementTree.fromstring(EMPTY_CHILD)
    sig = VulnerabilitySignature.create_from_element(e)

    assert sig.name is None
    assert sig.vendor_id == []
    assert sig.cve_id == []
    assert sig.category is None
    assert sig.severity is None
    assert sig.min_version is None
    assert sig.max_version is None
    assert sig.affected_host == []
    assert sig.default_action is None


def test_single_child():
    e = ElementTree.fromstring(SINGLE_CHILD)
    sig = VulnerabilitySignature.create_from_element(e)

    assert sig.vendor_id == ["one"]
    assert sig.cve_id == ["one"]
    assert sig.affected_host == ["server"]


def test_multi_child():
    e = ElementTree.fromstring(MULTI_CHILD)
    sig = VulnerabilitySignature.create_from_element(e)

    assert sig.vendor_id == ["one", "two"]
    assert sig.cve_id == ["one", "two"]
    assert sig.affected_host == ["server", "client"]
