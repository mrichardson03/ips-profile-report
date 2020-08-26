from __future__ import absolute_import, division, print_function

import os
import xml.etree.ElementTree as ElementTree

from panos_util.panorama import DeviceGroup, Panorama

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
    e = ElementTree.fromstring(DEVICE_GROUP)

    dg = DeviceGroup.create_from_element(e)
    rule_counts = dg.rule_counts()

    assert rule_counts["total"] == 6
    assert rule_counts["alert_only"] == 1
    assert rule_counts["blocks_criticals"] == 2
    assert rule_counts["blocks_high"] == 2
    assert rule_counts["blocks_medium"] == 2
    assert rule_counts["disabled"] == 1


def test_panorama():
    with open(os.path.join(os.path.dirname(__file__), "panorama.xml"), "r") as f:
        xml_doc = f.read()

    e = ElementTree.fromstring(xml_doc)
    p = Panorama.create_from_element(e)

    dg = p.get_device_group("DG-1")
    rule_counts = dg.rule_counts()

    assert rule_counts["total"] == 8
    assert rule_counts["alert_only"] == 1
    assert rule_counts["blocks_criticals"] == 5
    assert rule_counts["blocks_high"] == 3
    assert rule_counts["blocks_medium"] == 2
    assert rule_counts["disabled"] == 1
    assert rule_counts["drop"] == 1
