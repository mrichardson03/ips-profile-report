import xmltodict

from panos_util import VulnerabilityProfile

INTERNAL_VP = """
<entry name="Internal-VP">
    <rules>
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
    </rules>
</entry>
"""

ALERT_ONLY_VP = """
<entry name="Alert-Only-VP">
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

EXCEPTION_VP = """
<entry name="Exception-VP"/>
"""


def test_internal_vp():
    xmldict = xmltodict.parse(INTERNAL_VP)
    vp = VulnerabilityProfile.create_from_xmldict(xmldict)

    assert vp.name == 'Internal-VP'
    assert vp.blocks_criticals() is True
    assert vp.blocks_high() is True
    assert vp.blocks_medium() is False


def test_alert_only_vp():
    xmldict = xmltodict.parse(ALERT_ONLY_VP)
    vp = VulnerabilityProfile.create_from_xmldict(xmldict)

    assert vp.name == 'Alert-Only-VP'
    assert vp.blocks_criticals() is False
    assert vp.blocks_high() is False
    assert vp.blocks_medium() is False


def test_exception_vp():
    xmldict = xmltodict.parse(EXCEPTION_VP)
    vp = VulnerabilityProfile.create_from_xmldict(xmldict)

    assert vp.name == 'Exception-VP'
    assert vp.blocks_criticals() is False
    assert vp.blocks_high() is False
    assert vp.blocks_medium() is False
