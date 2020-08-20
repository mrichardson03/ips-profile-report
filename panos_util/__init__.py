from xml.etree import ElementTree

import xmltodict


def e_to_xmldict(element):
    """ Converts an ElementTree object to a dictionary parsed by xmltodict. """
    xml = ElementTree.tostring(element)
    return xmltodict.parse(xml)
