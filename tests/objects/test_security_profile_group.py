import xmltodict

from panos_util.objects import SecurityProfileGroup

EMPTY = """
<entry name="Empty"/>
"""

EMPTY_CHILD = """
<entry name="Empty-Child">
    <virus/>
    <spyware/>
    <vulnerability/>
    <url-filtering/>
    <wildfire-analysis/>
</entry>
"""

SINGLE_CHILD = """
<entry name="Single-Child">
    <virus>
        <member>one</member>
    </virus>
    <spyware>
        <member>one</member>
    </spyware>
    <vulnerability>
        <member>one</member>
    </vulnerability>
    <url-filtering>
        <member>one</member>
    </url-filtering>
    <wildfire-analysis>
        <member>one</member>
    </wildfire-analysis>
</entry>
"""


def test_empty():
    xmldict = xmltodict.parse(EMPTY)
    spg = SecurityProfileGroup.create_from_xmldict(xmldict)

    assert spg.name == "Empty"


def test_empty_child():
    xmldict = xmltodict.parse(EMPTY_CHILD)
    spg = SecurityProfileGroup.create_from_xmldict(xmldict)

    assert spg.name == "Empty-Child"
    assert spg.virus is None
    assert spg.spyware is None
    assert spg.vulnerability is None
    assert spg.url_filtering is None
    assert spg.wildfire_analysis is None


def test_single_child():
    xmldict = xmltodict.parse(SINGLE_CHILD)
    spg = SecurityProfileGroup.create_from_xmldict(xmldict)

    assert spg.name == "Single-Child"
    assert spg.virus == "one"
    assert spg.spyware == "one"
    assert spg.vulnerability == "one"
    assert spg.url_filtering == "one"
    assert spg.wildfire_analysis == "one"
