from collections import namedtuple


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
    @staticmethod
    def create_from_xmldict(xmldict):
        x = xmldict["entry"]

        name = x.get("@name", None)
        action = x.get("action", None)

        disabled = x.get("disabled", None)
        if disabled is not None:
            if disabled == "yes":
                disabled = True
            else:
                disabled = False
        else:
            disabled = False

        security_profile_group = None
        vulnerability_profile = None

        profile_setting = x.get("profile-setting", None)
        if profile_setting is not None:
            if "group" in profile_setting:
                group = profile_setting.get("group", None)
                security_profile_group = list(group.values())[0]
            else:
                profiles = profile_setting.get("profiles", None)
                if "vulnerability" in profiles:
                    vulnerability_profile = list(
                        profiles.get("vulnerability").values()
                    )[0]

        return SecurityRule(
            name, action, disabled, security_profile_group, vulnerability_profile
        )
