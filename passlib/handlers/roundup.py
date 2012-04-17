"""passlib.handlers.roundup - Roundup issue tracker hashes"""
#=========================================================
#imports
#=========================================================
#core
import logging; log = logging.getLogger(__name__)
#site
#libs
import passlib.utils.handlers as uh
from passlib.utils.compat import u
#pkg
#local
__all__ = [
    "roundup_plaintext",
    "ldap_hex_md5",
    "ldap_hex_sha1",
]
#=========================================================
#
#=========================================================
roundup_plaintext = uh.PrefixWrapper("roundup_plaintext", "plaintext",
                                     prefix=u("{plaintext}"), lazy=True,
    description="LDAP-style format storing a plaintext password - used by Roundup")

#NOTE: these are here because they're currently only known to be used by roundup
ldap_hex_md5 = uh.PrefixWrapper("ldap_hex_md5", "hex_md5", u("{MD5}"), lazy=True,
    description="LDAP-style format storing hex encoded MD5 digest - used by Roundup")
ldap_hex_sha1 = uh.PrefixWrapper("ldap_hex_sha1", "hex_sha1", u("{SHA}"), lazy=True,
    description="LDAP-style format storing hex encoded SHA1 digest - used by Roundup")

#=========================================================
#eof
#=========================================================
