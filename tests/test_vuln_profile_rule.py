import xmltodict

from panos_util.objects import VulnerabilityProfileRule

BLOCK_CRITICAL_HIGH = """
<entry name="Block-Critical-High">
    <action>
        <reset-both/>
    </action>
    <vendor-id>
        <member>any</member>
    </vendor-id>
    <severity>
        <member>critical</member>
        <member>high</member>
    </severity>
    <cve>
        <member>any</member>
    </cve>
    <threat-name>any</threat-name>
    <host>any</host>
    <category>any</category>
    <packet-capture>single-packet</packet-capture>
</entry>
"""

DEFAULT_MEDIUM_LOW_INFO = """
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
        <member>medium</member>
    </severity>
    <cve>
        <member>any</member>
    </cve>
    <threat-name>any</threat-name>
    <host>any</host>
    <category>any</category>
    <packet-capture>disable</packet-capture>
</entry>
"""


def test_block_critical_high():
    xmldict = xmltodict.parse(BLOCK_CRITICAL_HIGH)
    rule = VulnerabilityProfileRule.create_from_xmldict(xmldict["entry"])

    assert rule.name == "Block-Critical-High"
    assert rule.blocks_criticals() is True
    assert rule.blocks_high() is True
    assert rule.blocks_medium() is False


def test_default_medium_low_info():
    xmldict = xmltodict.parse(DEFAULT_MEDIUM_LOW_INFO)
    rule = VulnerabilityProfileRule.create_from_xmldict(xmldict["entry"])

    assert rule.name == "Default-Medium-Low-Info"
    assert rule.blocks_criticals() is False
    assert rule.blocks_high() is False
    assert rule.blocks_medium() is False
