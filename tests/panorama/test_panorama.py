import xmltodict

from panos_util.objects import SecurityProfileGroup, VulnerabilityProfile
from panos_util.panorama import DeviceGroup

RULES = """
<rules>
    <entry name="Strict">
        <action>allow</action>
        <profile-setting>
            <profiles>
                <vulnerability>
                    <member>strict</member>
                </vulnerability>
            </profiles>
        </profile-setting>
    </entry>
    <entry name="Default">
        <action>allow</action>
        <profile-setting>
            <profiles>
                <vulnerability>
                    <member>default</member>
                </vulnerability>
            </profiles>
        </profile-setting>
    </entry>
    <entry name="Disabled">
        <action>allow</action>
        <disabled>yes</disabled>
    </entry>
    <entry name="Drop">
        <action>drop</action>
    </entry>
    <entry name="Alert-Only">
        <action>allow</action>
        <profile-setting>
            <profiles>
                <vulnerability>
                    <member>Alert-Only</member>
                </vulnerability>
            </profiles>
        </profile-setting>
    </entry>
    <entry name="Profile-Group">
        <action>allow</action>
        <profile-setting>
            <group>
                <member>Profile-Group</member>
            </group>
        </profile-setting>
    </entry>
</rules>
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
</entry>
"""

PROFILE_GROUP = """
<entry name="Profile-Group">
    <vulnerability>
        <member>strict</member>
    </vulnerability>
</entry>
"""


def test_device_group():
    rules = DeviceGroup.parse_rules(RULES)

    vp_dict = xmltodict.parse(ALERT_ONLY)
    vuln_profiles = {"Alert-Only": VulnerabilityProfile.create_from_xmldict(vp_dict)}

    pg_dict = xmltodict.parse(PROFILE_GROUP)
    profile_groups = {
        "Profile-Group": SecurityProfileGroup.create_from_xmldict(pg_dict)
    }

    dg = DeviceGroup(rules, vuln_profiles, profile_groups)
    rule_counts = dg.rule_counts

    assert rule_counts["total"] == 6
    assert rule_counts["alert_only"] == 1
    assert rule_counts["blocks_criticals"] == 2
    assert rule_counts["blocks_high"] == 2
    assert rule_counts["blocks_medium"] == 2
    assert rule_counts["disabled"] == 1
