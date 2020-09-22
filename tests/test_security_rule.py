from __future__ import absolute_import, division, print_function

import xml.etree.ElementTree as ElementTree

from panos_util.policies import SecurityRule

EMPTY = """
<entry name="Empty"/>
"""

EMPTY_CHILD = """
<entry name="Empty-Child">
    <action/>
    <disabled/>
    <profile-setting/>
</entry>
"""

DISABLED = """
<entry name="Disabled">
    <disabled>yes</disabled>
</entry>
"""

DISABLED_NO = """
<entry name="Disabled-No">
    <disabled>no</disabled>
</entry>
"""

PROFILE_GROUP = """
<entry name="Profile-Group">
    <profile-setting>
        <group>
            <member>Profile-Group</member>
        </group>
    </profile-setting>
</entry>
"""

EMPTY_PROFILE_SETTING = """
<entry name="Empty-Profile-Setting">
    <profile-setting/>
</entry>
"""

VULN_PROFILE = """
<entry name="Vuln-Profile">
    <profile-setting>
        <profiles>
            <vulnerability>
                <member>Vuln-Profile</member>
            </vulnerability>
        </profiles>
    </profile-setting>
</entry>
"""

NO_VULN_PROFILE = """
<entry name="No-Vuln-Profile">
    <profile-setting>
        <profiles>
            <virus>
                <member>No-Vuln-Profile</member>
            </virus>
        </profiles>
    </profile-setting>
</entry>
"""


def test_empty():
    e = ElementTree.fromstring(EMPTY)
    r = SecurityRule.create_from_element(e)

    assert r.name == "Empty"


def test_empty_child():
    e = ElementTree.fromstring(EMPTY_CHILD)
    r = SecurityRule.create_from_element(e)

    assert r.name == "Empty-Child"
    assert r.action is None
    assert r.disabled is False
    assert r.security_profile_group is None
    assert r.vulnerability_profile is None


def test_disabled():
    e = ElementTree.fromstring(DISABLED)
    r = SecurityRule.create_from_element(e)

    assert r.name == "Disabled"
    assert r.disabled is True


def test_disabled_no():
    e = ElementTree.fromstring(DISABLED_NO)
    r = SecurityRule.create_from_element(e)

    assert r.name == "Disabled-No"
    assert r.disabled is False


def test_profile_group():
    e = ElementTree.fromstring(PROFILE_GROUP)
    r = SecurityRule.create_from_element(e)

    assert r.name == "Profile-Group"
    assert r.security_profile_group == "Profile-Group"
    assert r.vulnerability_profile is None


def test_empty_profile_setting():
    e = ElementTree.fromstring(EMPTY_PROFILE_SETTING)
    r = SecurityRule.create_from_element(e)

    assert r.name == "Empty-Profile-Setting"
    assert r.security_profile_group is None
    assert r.vulnerability_profile is None


def test_vuln_profile():
    e = ElementTree.fromstring(VULN_PROFILE)
    r = SecurityRule.create_from_element(e)

    assert r.name == "Vuln-Profile"
    assert r.security_profile_group is None
    assert r.vulnerability_profile == "Vuln-Profile"


def test_no_vuln_profile():
    e = ElementTree.fromstring(NO_VULN_PROFILE)
    r = SecurityRule.create_from_element(e)

    assert r.name == "No-Vuln-Profile"
    assert r.vulnerability_profile is None
