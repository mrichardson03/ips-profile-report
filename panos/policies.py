class SecurityRule:

    def __init__(self, name, action, disabled, security_profile_group, vulnerability_profile):
        self._name = name
        self._action = action
        self._disabled = disabled
        self._security_profile_group = security_profile_group
        self._vulnerability_profile = vulnerability_profile

    @property
    def name(self):
        return self._name

    @property
    def action(self):
        return self._action

    @property
    def disabled(self):
        return self._disabled

    @property
    def security_profile_group(self):
        return self._security_profile_group

    @security_profile_group.setter
    def security_profile_group(self, value):
        self._security_profile_group = value

    @property
    def vulnerability_profile(self):
        return self._vulnerability_profile

    @vulnerability_profile.setter
    def vulnerability_profile(self, value):
        self._vulnerability_profile = value

    @staticmethod
    def create_from_xmldict(xmldict):
        name = xmldict['entry']['@name']
        action = xmldict['entry']['action']
        if 'disabled' in xmldict['entry'] and xmldict['entry']['disabled'] == 'yes':
            disabled = True
        else:
            disabled = False

        security_profile_group = None
        vulnerability_profile = None

        if 'profile-setting' in xmldict['entry']:
            if 'group' in xmldict['entry']['profile-setting']:
                if xmldict['entry']['profile-setting']['group'] is not None:
                    security_profile_group = list(xmldict['entry']['profile-setting']['group'].values())[0]
            elif 'profiles' in xmldict['entry']['profile-setting']:
                if xmldict['entry']['profile-setting']['profiles'] is not None:
                    if 'vulnerability' in xmldict['entry']['profile-setting']['profiles']:
                        vulnerability_profile = list(xmldict['entry']['profile-setting']['profiles']['vulnerability'].values())[0]

        return SecurityRule(name, action, disabled, security_profile_group, vulnerability_profile)
