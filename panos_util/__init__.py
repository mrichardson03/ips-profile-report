__version__ = "2.0.0.b4"


def strip_empty(s: str) -> str:
    """ If s is empty, return None.

        This is needed because getting the text attribute for an XML element returns
        an empty string if the element is empty.  For example, the text attribute of
        XML element '<element/>' will be the empty string, not None.
    """
    if s == "":
        return None
    else:
        return s
