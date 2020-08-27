from __future__ import absolute_import, annotations, division, print_function

from collections import namedtuple
from xml.etree.ElementTree import Element

from . import strip_empty


class SecurityRule(
    namedtuple(
        "SecurityRule",
        [
            "name",
            "action",
            "disabled",
            "security_profile_group",
            "vulnerability_profile",
        ],
    )
):
    """ Class representing a security rule. """

    @staticmethod
    def create_from_element(e: Element) -> SecurityRule:
        """ Create SecurityRule from XML element. """
        name = e.get("name")
        action = strip_empty(e.findtext("action"))

        disabled = strip_empty(e.findtext("disabled"))
        if disabled == "yes":
            disabled = True
        else:
            disabled = False

        security_profile_group = strip_empty(
            e.findtext(".//profile-setting/group/member")
        )
        vulnerability_profile = strip_empty(
            e.findtext(".//profile-setting/profiles/vulnerability/member")
        )

        return SecurityRule(
            name, action, disabled, security_profile_group, vulnerability_profile
        )
