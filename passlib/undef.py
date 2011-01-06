"""bps.undef -- undefined singleton - import from types"""
#=========================================================
#imports
#=========================================================
#local
__all__ = [
    'Undef',
    'defined','undefined',
    'strip_undefined_keys',
]
#=========================================================
#"undefined" singleton
#=========================================================
#TODO: figure out how to play nice w/ peak's NOT_GIVEN, mako's Undefined,
# and any other instances of this singleton
# eg: could have bps check an env var for the name of a constant to import
# instead of Undef=UndefType()

class UndefType(object):
    "class whose single instance is the Undef object"
    def __nonzero__(self):
        return False
    def __str__(self):
        return "Undef"
    def __repr__(self):
        return "Undef"
    def __eq__(self, value):
        return False #never equal to anything, including itself :)
    def __ne__(self, value):
        return True #never equal to anything, including itself :)
Undef = UndefType()

def defined(value):
    return value is not Undef

def undefined(value):
    return value is Undef

def strip_undefined_keys(source, inplace=False):
    "remove any keys from dict whose value is Undef; returns resulting dict"
    if inplace:
        remove = set(
            k
            for k,v in source.iteritems()
            if v is Undef
        )
        for k in remove:
            del source[k]
        return source
    else:
        return dict(
            (k,v)
            for k,v in source.iteritems()
            if v is not Undef
        )

#=========================================================
#
#=========================================================
