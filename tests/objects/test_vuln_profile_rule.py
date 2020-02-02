import xmltodict

from panos.objects import VulnerabilityProfileRule


EMPTY = """
<entry name="Empty"/>
"""

EMPTY_TAGS = """
<entry name="Empty-Multi">
    <vendor-id/>
    <cve/>
    <severity/>
    <action/>
</entry>
"""

BLOCK_CRITICAL_HIGH = """
<entry name="Block-Critical-High">
    <action>
        <reset-both/>
    </action>
    <vendor-id>
        <member>one</member>
        <member>two</member>
    </vendor-id>
    <severity>
        <member>critical</member>
        <member>high</member>
    </severity>
    <cve>
        <member>one</member>
        <member>two</member>
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

ALERT_ALL = """
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
"""


def test_empty():
    xmldict = xmltodict.parse(EMPTY)
    rule = VulnerabilityProfileRule.create_from_xmldict(xmldict['entry'])


def test_empty_tags():
    xmldict = xmltodict.parse(EMPTY_TAGS)
    rule = VulnerabilityProfileRule.create_from_xmldict(xmldict['entry'])

    


def test_block_critical_high():
    xmldict = xmltodict.parse(BLOCK_CRITICAL_HIGH)
    rule = VulnerabilityProfileRule.create_from_xmldict(xmldict['entry'])

    assert rule.name == 'Block-Critical-High'
    assert rule.blocks_criticals() is True
    assert rule.blocks_high() == True
    assert rule.blocks_medium() == False
    assert rule.alert_only() == False

    assert rule.vendor_id == ['one', 'two']
    assert rule.severity == ['critical', 'high']
    assert rule.cve == ['one', 'two']
    assert rule.threat_name == 'any'
    assert rule.host == 'any'
    assert rule.packet_capture == 'single-packet'


def test_default_medium_low_info():
    xmldict = xmltodict.parse(DEFAULT_MEDIUM_LOW_INFO)
    rule = VulnerabilityProfileRule.create_from_xmldict(xmldict['entry'])

    assert rule.name == 'Default-Medium-Low-Info'
    assert rule.action == 'default'

    assert rule.blocks_criticals() == False
    assert rule.blocks_high() == False
    assert rule.blocks_medium() == False

    assert rule.vendor_id == ['any']

    assert rule.packet_capture == 'disable'


def test_alert():
    xmldict = xmltodict.parse(ALERT_ALL)
    rule = VulnerabilityProfileRule.create_from_xmldict(xmldict['entry'])

    assert rule.name == 'Alert-All'
    assert rule.action == 'alert'

    assert rule.alert_only() == True
