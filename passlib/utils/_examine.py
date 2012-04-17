"""passlib.utils._examine -- internal helpers to examine handlers"""
#=========================================================
#imports
#=========================================================
# core
# package
from passlib.registry import get_crypt_handler
from passlib.utils import is_crypt_handler, has_salt_info, has_rounds_info
# local

#=========================================================
# internal constants
#=========================================================

# handlers which aren't hashes (used by get_type)
_disabled_handlers = ["unix_fallback", "unix_disabled", "django_disabled"]

# plaintext handlers (used by get_type)
_plaintext_handlers = ["plaintext", "roundup_plaintext", "ldap_plaintext"]

# 'user' keyword not required
_user_optional_handlers = ["cisco_pix"]

# handlers which match pretty much anything
_wildcard_identify_handlers = [
    "plaintext",
    "ldap_plaintext",
    "unix_fallback",
    "unix_disabled",
]

#=========================================================
# internal helpers
#=========================================================
def _handler(source, errname="value"):
    "resolve name/handler -> handler"
    if is_crypt_handler(source):
        return source
    elif isinstance(source, str):
        return get_crypt_handler(source)
    else:
        raise TypeError("%s must be handler or handler name" % (errname,))

def _name(source, errname="value"):
    "resolve name/handler -> name"
    if is_crypt_handler(source):
        return source.name
    elif isinstance(source, str):
        return source
    else:
        raise TypeError("%s must be handler or handler name" % (errname,))

def _pair(source, errname="value"):
    if is_crypt_handler(source):
        return source, source.name
    elif isinstance(source, str):
        return get_crypt_handler(source), source
    else:
        raise TypeError("%s must be handler or handler name" % (errname,))

#=========================================================
# categorization
#=========================================================
def handler_type(source):
    """category type of handler.

    * ``"disabled"`` - disabled account helper
    * ``"plaintext"`` - plaintext handler
    * ``"fixed"`` - fixed-rounds handler
    * ``"linear"`` - variable-rounds handler w/ linear cost
    * ``"log2"`` - variable-rounds handler w/ log2 cost
    """
    handler, name = _pair(source)
    if name in _disabled_handlers:
        return "disabled"
    if name in _plaintext_handlers:
        return "plaintext"
    return getattr(handler, "rounds_cost", "fixed")

def is_variable(source):
    "does handler have variable cost?"
    return 'rounds' in _handler(source).setting_kwds
has_rounds = is_variable

def is_wrapper(source):
    "is handler a wrapper for another?"
    # NOTE: this assumes all wrappers are PrefixWrapper instances
    return hasattr(_handler(source), "orig_prefix")

def is_psuedo(source):
    "is handler a plaintext/disabled handler?"
    name = _name(source)
    return name in _disable_handlers or name in _plaintext_handlers

#=========================================================
# properties
#=========================================================
def has_user(source):
    "does handler support user context?"
    return 'user' in _handler(source).context_kwds

def has_optional_user(source):
    "does handler support user context, but not require it?"
    return _name(source) in _user_optional_handlers

def has_wildcard_identify(source):
    "does handler have a wildcard identify?"
    return _name(source) in _wildcard_identify_handlers

def has_unique_identify(source):
    "can handler's identify be trusted to not have false positives?"
    handler, name = _pair(source)
    if name in _greedy_identify_handlers:
        return False
    # XXX: any more?
    if getattr(handler, "ident", None):
        return True
    if getattr(handler, "ident_values", None):
        return True
    return False

def has_salt(source):
    return 'salt' in _handler(source).setting_kwds

def has_salt_size(source):
    return 'salt_size' in _handler(source).setting_kwds

def has_many_idents(source):
    return 'ident' in _handler(source).setting_kwds

def iter_ident_values(source):
    handler = _handler(source)
    ident = getattr(handler, "ident", None)
    if ident:
        yield ident
    ident_values = getattr(handler, "ident_values", None)
    if ident_values:
        for ident in ident_values:
            yield ident

def description(source):
    return getattr(_handler(source), "description", None)

#=========================================================
# eof
#=========================================================
