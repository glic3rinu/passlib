"""passlib.utils._identify - fuzzy hash identification

these routines are mainly useful to attempt to identify
unknown hash formats. they are currently rather rough,
full of weird heuristics, and mainly intended for use by
the :cmd:`passlib identify` command line tool.
"""
#=========================================================
#imports
#=========================================================
from __future__ import division
# core
import re
# package
import passlib.utils._examine as examine
import passlib.utils.handlers as uh
# local
__all__ =[
    "fuzzy_identify_hash",
    "identify_hash_format",
]
#=========================================================
# constants
#=========================================================

# some handlers lack fixed identifier, and may match against hashes
# that aren't their own; this is used to rate those as less likely.
_handler_weights = dict(
    des_crypt=90,
    bigcrypt=25,
    crypt16=25,
)

# list of known character ranges
_char_ranges = [
    uh.LOWER_HEX_CHARS,
    uh.UPPER_HEX_CHARS,
    uh.HEX_CHARS,
    uh.HASH64_CHARS,
    uh.BASE64_CHARS,
]

#=========================================================
# identify commands
#=========================================================

def _identify_char_range(source):
    "identify if source string uses known character range"
    source = set(source)
    for cr in _char_ranges:
        if source.issubset(cr):
            return cr
    return None

def _identify_helper(hash, handler):
    """try to interpret hash as belonging to handler, report results
    :arg hash: hash string to check
    :arg handler: handler to check against
    :returns:
        ``(category, score)``, where category is one of:

        * ``"hash"`` -- if parsed correctly as hash string
        * ``"salt"`` -- if parsed correctly as salt / configuration string
        * ``"malformed"`` -- if identified, but couldn't be parsed
        * ``None`` -- no match whatsoever
    """
    # fix odds of identifying malformed vs other hash
    malformed = 75

    # check if handler identifies hash
    if not handler.identify(hash):
        # last-minute check to see if it *might* be one,
        # but identify() method was too strict.
        if isinstance(hash, bytes):
            hash = hash.decode("utf-8")
        if any(hash.startswith(ident) for ident in
               examine.iter_ident_values(handler)):
            return "malformed", malformed
        return None, 0

    # apply hash-specific fuzz checks (if any).
    # currently only used by cisco_type7
    fid = getattr(handler, "_fuzzy_identify", None)
    if fid:
        score = fid(hash)
        assert 0 <= score <= 100
        if score == 0:
            return None, 0
    else:
        score = 100

    # first try to parse the hash using GenericHandler.from_string(),
    # since that's cheaper than always calling verify()
    if hasattr(handler, "from_string"):
        try:
            hobj = handler.from_string(hash)
        except ValueError:
            return "malformed", malformed
        checksum = hobj.checksum

        # detect salts
        if checksum is None:
            return "config", score

        # if checksum contains suspiciously fewer chars than it should
        # (e.g. is strictly hex, but should be h64), weaken score.
        # uc>1 is there so we skip 'fake' checksums that are all one char.
        uc = len(set(checksum))
        chars = getattr(handler, "checksum_chars", None)
        if isinstance(checksum, unicode) and uc > 1 and chars:
            cr = _identify_char_range(checksum)
            hr = _identify_char_range(chars)
            if (cr in [uh.LOWER_HEX_CHARS, uh.UPPER_HEX_CHARS] and
                    hr in [uh.HASH64_CHARS, uh.BASE64_CHARS]):
                # *really* unlikely this belongs to handler.
                return None, 0
        return "hash", score

    # as fallback, try to run hash through verify & genhash and see
    # if any errors are thrown.
    else:

        # prepare context kwds
        ctx = {}
        if examine.is_user_optional(handler):
            ctx['user'] = 'user'

        # check if it verifies against password
        try:
            ok = handler.verify('xxx', hash, **ctx)
        except ValueError:
            pass
        else:
            return "hash", score

        # check if we can encrypt against password
        try:
            handler.genhash('xxx', hash, **ctx)
        except ValueError:
            pass
        else:
            return "config", score

        # identified, but can't parse
        return "malformed", malformed

def fuzzy_identify(hash):
    """try to identify format of hash.

    :arg hash: hash to try to identify
    :returns:
        list of ``(name, category, confidence)`` entries.
        * ``name`` -- name of handler
        * ``category`` -- one of ``"hash", "salt", "malformed", "guess"``
        * ``confidence`` -- confidence rating used to rank possibilities.
          currently rather arbitrary and inexact.
    """
    # gather results, considering all handlers which don't use wildcard identify
    results = []
    for name in examine.list_crypt_handlers():
        if examine.has_wildcard_identify(name):
            continue
        handler = examine.get_crypt_handler(name)
        cat, score = _identify_helper(hash, handler)
        if cat:
            score *= _handler_weights.get(name, 100) // 100
            results.append([name, cat, score])

    # sort by score and return
    so = ["hash", "config", "malformed"]
    def sk(record):
        return -record[2], so.index(record[1]), record[0]
    results.sort(key=sk)
    return results

def identify_hash_format(hash):
    """detect if a hash belongs to one of a few known classes of formats.

    :returns:
        ``(format, identifer)`` tuple,
        where format is one of ``"mcf"``, ``"ldap"``, or ``None`` (unknown);
        and identifier is the mcf/ldap identifier or ``None``.
    """
    m = re.match(r"(\$[a-zA-Z0-9_-]+\$)\w+", candidate)
    if m:
        return "mcf", m.group(1)
    m = re.match(r"(\{\w+\})\w+", candidate)
    if m:
        return "ldap", m.group(1)
    return None, None

#=========================================================
# eof
#=========================================================
