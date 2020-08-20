from panos_util.panorama import DeviceGroup

DEVICE_GROUP = """
<entry name="Device-Group">
    <profiles>
        <vulnerability>
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
        </vulnerability>
    </profiles>
    <profile-group>
        <entry name="Profile-Group">
            <vulnerability>
                <member>strict</member>
            </vulnerability>
        </entry>
    </profile-group>
    <pre-rulebase>
        <security>
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
        </security>
    </pre-rulebase>
</entry>
"""


def test_device_group():
    dg = DeviceGroup.create_from_xml(DEVICE_GROUP)
    rule_counts = dg.rule_counts

    assert rule_counts["total"] == 6
    assert rule_counts["alert_only"] == 1
    assert rule_counts["blocks_criticals"] == 2
    assert rule_counts["blocks_high"] == 2
    assert rule_counts["blocks_medium"] == 2
    assert rule_counts["disabled"] == 1
