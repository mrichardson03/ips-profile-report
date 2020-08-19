import xmltodict

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
    xmldict = xmltodict.parse(EMPTY)
    r = SecurityRule.create_from_xmldict(xmldict)

    assert r.name == "Empty"


def test_empty_child():
    xmldict = xmltodict.parse(EMPTY_CHILD)
    r = SecurityRule.create_from_xmldict(xmldict)

    assert r.name == "Empty-Child"
    assert r.action is None
    assert r.disabled is False
    assert r.security_profile_group is None
    assert r.vulnerability_profile is None


def test_disabled():
    xmldict = xmltodict.parse(DISABLED)
    r = SecurityRule.create_from_xmldict(xmldict)

    assert r.name == "Disabled"
    assert r.disabled is True


def test_disabled_no():
    xmldict = xmltodict.parse(DISABLED_NO)
    r = SecurityRule.create_from_xmldict(xmldict)

    assert r.name == "Disabled-No"
    assert r.disabled is False


def test_profile_group():
    xmldict = xmltodict.parse(PROFILE_GROUP)
    r = SecurityRule.create_from_xmldict(xmldict)

    assert r.name == "Profile-Group"
    assert r.security_profile_group == "Profile-Group"
    assert r.vulnerability_profile is None


def test_empty_profile_setting():
    xmldict = xmltodict.parse(EMPTY_PROFILE_SETTING)
    r = SecurityRule.create_from_xmldict(xmldict)

    assert r.name == "Empty-Profile-Setting"
    assert r.security_profile_group is None
    assert r.vulnerability_profile is None


def test_vuln_profile():
    xmldict = xmltodict.parse(VULN_PROFILE)
    r = SecurityRule.create_from_xmldict(xmldict)

    assert r.name == "Vuln-Profile"
    assert r.security_profile_group is None
    assert r.vulnerability_profile == "Vuln-Profile"


def test_no_vuln_profile():
    xmldict = xmltodict.parse(NO_VULN_PROFILE)
    r = SecurityRule.create_from_xmldict(xmldict)

    assert r.name == "No-Vuln-Profile"
    assert r.vulnerability_profile is None
