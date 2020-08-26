import xml.etree.ElementTree as ElementTree

from panos_util.objects import (
    DefaultVulnerabilityProfile,
    StrictVulnerabilityProfile,
    VulnerabilityProfile,
)

EMPTY = """
<entry name="Empty"/>
"""

BLOCK_ALL = """
<entry name="Block-All">
    <rules>
        <entry name="Block-Critical-High-Medium">
            <action>
                <reset-both/>
            </action>
            <vendor-id>
                <member>any</member>
            </vendor-id>
            <severity>
                <member>critical</member>
                <member>high</member>
                <member>medium</member>
            </severity>
            <cve>
                <member>any</member>
            </cve>
            <threat-name>any</threat-name>
            <host>any</host>
            <category>any</category>
            <packet-capture>single-packet</packet-capture>
        </entry>
        <entry name="Default-Medium-Low-Info">
            <action>
                <default/>
            </action>
            <vendor-id>
                <member>any</member>
            </vendor-id>
            <severity>
                <member>low</member>
                <member>informational</member>
            </severity>
            <cve>
                <member>any</member>
            </cve>
            <threat-name>any</threat-name>
            <host>any</host>
            <category>any</category>
            <packet-capture>disable</packet-capture>
        </entry>
    </rules>
</entry>
"""

ALERT_ONLY = """
<entry name="Alert-Only">
    <rules>
        <entry name="Alert-All">
            <action>
                <alert/>
            </action>
            <vendor-id>
                <member>any</member>
            </vendor-id>
            <severity>
                <member>any</member>
            </severity>
            <cve>
                <member>any</member>
            </cve>
            <threat-name>any</threat-name>
            <host>any</host>
            <category>any</category>
            <packet-capture>disable</packet-capture>
        </entry>
    </rules>
    <threat-exception>
    <entry name="57497">
        <action>
        <reset-both/>
        </action>
    </entry>
    <entry name="57570">
        <action>
        <reset-both/>
        </action>
    </entry>
    </threat-exception>
</entry>
"""


def test_default():
    vp = DefaultVulnerabilityProfile()

    assert vp.name == "default"
    assert vp.blocks_criticals() is False
    assert vp.blocks_high() is False
    assert vp.blocks_medium() is False
    assert vp.alert_only() is False


def test_strict():
    vp = StrictVulnerabilityProfile()

    assert vp.name == "strict"
    assert vp.blocks_criticals() is True
    assert vp.blocks_high() is True
    assert vp.blocks_medium() is True
    assert vp.alert_only() is False


def test_empty():
    e = ElementTree.fromstring(EMPTY)
    vp = VulnerabilityProfile.create_from_element(e)

    assert vp.name == "Empty"
    assert vp.blocks_criticals() is False
    assert vp.blocks_high() is False
    assert vp.blocks_medium() is False
    assert vp.alert_only() is False


def test_block_all():
    e = ElementTree.fromstring(BLOCK_ALL)
    vp = VulnerabilityProfile.create_from_element(e)

    assert vp.name == "Block-All"
    assert vp.blocks_criticals() is True
    assert vp.blocks_high() is True
    assert vp.blocks_medium() is True
    assert vp.alert_only() is False


def test_alert_only_vp():
    e = ElementTree.fromstring(ALERT_ONLY)
    vp = VulnerabilityProfile.create_from_element(e)

    assert vp.name == "Alert-Only"
    assert vp.blocks_criticals() is False
    assert vp.blocks_high() is False
    assert vp.blocks_medium() is False
    assert vp.alert_only() is True
