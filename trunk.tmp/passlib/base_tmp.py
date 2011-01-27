
#=========================================================
#
#=========================================================
class CryptAlgorithmHelper(CryptAlgorithm):
    """helper class for implementing CryptAlgorithms.


    this class provides

    """

    #=========================================================
    #implementation of CryptAlgorithm frontend
    #=========================================================
    @classmethod
    def identify(cls, hash):
        #NOTE: default identify() implementation,
        # uses _parse() method as backend
        return bool(hash and cls._parse(hash))

    @classmethod
    def encrypt(cls, secret, hash=None, keep_salt=False, **kwds):
        #NOTE: default encrypt() implementation,
        # uses _parse(), _encrypt(), _render() methods as backend
        for key in cls._forbid_encrypt_kwds:
            if key in kwds:
                raise KeyError, "keyword %r not allowed for encrypt method"
        if hash:
            opts = cls._parse(hash)
            opts.update(kwds)
            if not keep_salt:
                del opts['salt']
            del opts['checksum']
        else:
            opts = kwds
        opts = cls._prepare(**opts)
        opts['checksum'] = self._encrypt(secret, **opts)
        return cls._render(**kwds)

    @classmethod
    def verify(cls, secret, hash, **kwds):
        #NOTE: default verify() implementation,
        # uses _parse() and _encrypt() methods as backend
        for key in kwds:
            if key not in cls.context_kwds:
                if cls.context_kwds:
                    raise TypeError, "keyword %s not allowed, only %s" % (key, ", ".join(cls.context_kwds))
                else:
                    raise TypeError, "keyword %s not allowed"
        #NOTE: 'kwds' should be restricted to context_kwds, if any
        if hash is None:
            return False
        opts = cls._parse(hash)
        opts.update(kwds)
        checksum = opts.pop("checksum")
        return opts['checksum'] == self._encrypt(secret, **opts)

    #=========================================================
    #class attrs
    #=========================================================
    _forbid_encrypt_kwds = ("salt", "checksum") #don't allow user to override these via encrypt(), must be pulled from hash
    _repr_attrs = ("ident", "salt", "rounds", "checksum")

    #=========================================================
    #instance attrs
    #=========================================================
    ident = None #identifier portion of hash
    salt = None #salt portion of hash
    rounds = None #number of rounds used
    checksum = None #checksum portion of hash

    #=========================================================
    #constructor
    #=========================================================
    def __init__(self, ident=None, salt=None, rounds=None, checksum=None, **kwds):
        self.__super = super(CryptAlgorithm, self)
        self.__super.__init__(**kwds)
        if ident:
            self.ident = ident
        self.checksum = checksum
        if salt:
            if not self.has_salt:
                raise ValueError, "%s algorithm does not use a salt" % (self.name,)
            self.salt = salt
        if rounds:
            if not self.has_rounds:
                raise ValueError, "%s algorithm does not use rounds" % (self.name,)
            self.rounds = rounds

    def __repr__(self):
        tail = ', '.join(
            "%s=%r" % (key, getattr(self,key))
            for key in self._repr_attrs
            if key in self.__dict__
        )
        c = self.__class__
        return "%s.%s(%s)" % (c.__module__,c.__name__, tail)


    #=========================================================
    #SimpleCryptAlgorithm backend
    #=========================================================
    @abstract_class_method
    def _parse(self, hash):
        """parse hash, returning dict containing components, or None if no match"""

    @abstractmethod
    def _encrypt(self, secret):
        "generate checksum for specified secret using settings stored in instance"

    @abstractmethod
    def _render(self):
        "render hash instance to string"

    #=========================================================
    #rounds helpers
    #=========================================================

    _rounds = None

    def _get_rounds(self):
        return self._rounds

    def _set_rounds(self, value):
        if value is None:
            pass
        elif not self.has_rounds:
            raise AttributeError, "algorithm does not support rounds option"
        else:
            value = self._resolve_preset_rounds(value)
        self._rounds = value
    rounds = property(_get_rounds, _set_rounds)

    #=========================================================
    #eoc
    #=========================================================
