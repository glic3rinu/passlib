"""bps.security.policy -- simple framework for defining internal application security policies.

.. todo::

    * finish documentation for this module

    * go through whole thing and mark out the funcs
      which accept a (comma-separated) string in place of a list of roles.
      make handling of that uniform and add tests
      (maybe via norm_role_seq() helper)

"""
#=========================================================
#imports
#=========================================================
#core
from sys import version_info as pyver
from collections import deque
import inspect
#pkg
from bps import *
from bps.text import split_condense, condense
from bps.meta import isstr, isseq
from bps.basic import intersects
#local
__all__ = [
    'Policy',
##    'PERM',
]

#=========================================================
#constants
#=========================================================
class PERM:
    """class holding permission-response constants.

    This class is used to contain the constants
    which are used by :meth:`Permission.check` and the :class:`Permission`
    class' ``guard`` function to signal it's response to a given permission question:

    .. attribute:: ALLOW

        Indicates permission is explicitly *allowed*.

    .. attribute:: DENY

        Indicates permission is explicitly *denied*.

    .. attribute:: PENDING

        Indicates permission is neither granted *or* denied,
        and that the decision is still pending, and should
        be decided by the other permission instances in the policy.
    """
    ALLOW = "allow"
    DENY = "deny"
    PENDING = "pending"

    values = (ALLOW, DENY, PENDING)

#=========================================================
#role class - used internally by Policy
#=========================================================
class Role(BaseClass):
    """Defines a single role within a Policy.

    Instances of this class have the following attributes (passed in via constructor):

    :type name: str
    :arg name:
        The name of the role.

    :type inherits: seq(str)|None
    :param inherits:
        Specifies the names of other roles which this should "inherit"
        the permissions of. this allows roles to be nested hierarchically.

    :type desc: str|None
    :param desc:
        Optional string describing role for user-display purposes.
        Defaults to empty string.

    :type title: str|None
    :param title:
        Optional string to identify role for user-display purposes,
        defaults to capitalized version of ``name``.

    :type grantable: bool
    :param grantable:
        This is a flag used to differentiate between
        roles that can be granted to the user (default, ``True``),
        and roles that the user cannot be granted,
        such roles can only be used to inherit from.

        This is more a matter of policy enforcement for your application,
        if you don't wish to use this feature, leave it alone,
        and the default will cause it to never activate.

    .. note::

        Only name should be specified as positional arguments.
        (previous inherits & desc were, but rescinding that for now).
    """
    #=========================================================
    #class attrs
    #=========================================================

    #=========================================================
    #instance attrs
    #=========================================================
##    policy = weakref_property("_policy")

    name = None #name of role used for matching
    title = None #human readable version of name
    desc = None #optional human readable description of role
    inherits = None #list of other roles which this inherits the permissions of
    grantable = True

    #=========================================================
    #init
    #=========================================================
    def __init__(self, name, inherits=None, desc=None, title=None, grantable=None):
        if not name:
            raise ValueError, "Role name must be specified"
        self.name = name
        self.title = title or self.name.capitalize()
        self.desc = desc
        if grantable is not None:
            self.grantable = grantable
        if inherits is None:
            self.inherits = frozenset()
        elif isstr(inherits):
            self.inherits = frozenset(split_condense(inherits))
        else:
            self.inherits = frozenset(inherits)

    #=========================================================
    #helpers
    #=========================================================
    def __repr__(self):
        return '<Role 0x%x %r>'%(id(self), self.name)

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#permission class - used internally by Policy
#=========================================================
class Permission(BaseClass):
    """Defines a single permission with a policy.

    Instances of this class have the following attributes (passed in via constructor):

    :type action: str
    :arg action:
        the action string which this permission must match

    :type klass: str|None|False|True
    :arg klass:
        The name of the class which the action is performed on.
        ``False`` means match only if klass is ``None``.
        ``None`` (the default) means match ignoring the value of klass.
        ``True`` means match only if klass is NOT ``None``.
        Any other string means match only if klass matches the string.

    :type attrs: seq(str)|None
    :arg attrs:
        If ``None`` (the default), matches any and all attributes.
        If specified, matches if the attribute specified is within the list,
        or if no attribute is specified.

    :type guard: callable|None
    :arg guard:
        Optional callable function which controls whether permission
        will be granted. If permission does not match all the above
        parameters, guard will not be called. If permission does match,
        and guard is specified, it will be invoked with the following keywords:
        "user", "action", "klass", "item", "attr", "target".

        Inspection will be used to determine which keywords the guard accepts,
        and only those which are both defined and accepted by the guard function
        will be passed in.

        * The action is permitted if the guard returns ``True``
        * Checking will continue with other permission objects if the guard
          returns ``False``.
        * The action will be explictly denied (no further checks made)
          if the guard returns the special singleton :data:`PERM_DENIED`.

    :type desc: str|None
    :param desc:
        optional string describing what this permits in human-readable terms;
        eg, for display to the user.
        if not specified, the docstring from the guard function will be used,
        if available.

    :type deny: bool
    :param deny:
        If this is set to ``True``, when the permission matches,
        it will deny access rather than allow it.
        (Thus, if the guard returns ``True``, access is denied).

    :type priority: int
    :param priority:
        Optionally, you can specify a priority for the permission.
        Permissions with a higher priority will match before
        permissions with a lower priority.
        This is useful to issue generic permission patterns,
        and then override specific sub-matches with a higher
        priority ``deny=True`` permission.
        The default priority is 0.

    See :ref:`permission-question` for an overview of how
    these attributes should be used to represent
    real-world permission issues.

    Instances of this class should not be created directly,
    but via :meth:`Policy.permit`.

    The policy class defines only one method of note:

    .. automethod:: check
    """
    #=========================================================
    #class attrs
    #=========================================================
    #list of all possible kwds that could be sent to guard func
    all_guard_kwds = ("user", "action", "klass", "attr", "item", "scope", "perm")

    #=========================================================
    # instance attrs
    #=========================================================
##    policy = weakref_property("_policy")
    action = None #name of action this matches
    desc = None #human readable text describing permission
    klass = None #name of klass this matches, if False it matches NO class, if None if matches all
    attrs = None #list of klass' attrs this matches, False if matches no property, or None if matches all
    guard = None #optional guard func which is checked if all other parts match
    guard_kwds = None #subset of all_guard_kwds which guard func actually accepts
    deny = False #if true, permission will DENY rather than ALLOW
    priority = 0

    #=========================================================
    #init
    #=========================================================
    def __init__(self, action, klass=None,
            attrs=None, guard=None, desc=None, deny=False,
            priority=0):

        #store actions
        self.action = action
        self.desc = desc or (guard and guard.__doc__) or None
        ##if klass and hasattr(klass, "__name__"):
        ##    klass = klass.__name__
        self.klass = klass
        if attrs is not None:
            if not attrs:
                self.attrs = frozenset([None])
            else:
                self.attrs = frozenset(attrs)
        self.guard = guard
        self.deny = deny
        self.priority = priority

        #build list of kwds which guard accepts
        if guard:
            fmt = inspect.getargspec(guard)
            if fmt[2]: #accepts **kwds
                self.guard_kwds = frozenset(self.all_guard_kwds)
            else:
                self.guard_kwds = frozenset(
                    key for key in self.all_guard_kwds
                    if key in fmt[0]
                    )

    #=========================================================
    #main interface
    #=========================================================
    def check(self, user, action,
              klass=None, item=None, attr=None,
              scope=None, _enable_guard=True):
        """check if user has permission to perform the specified action.

        :arg user:
            [required]
            The user object to check against.
            This is not used inside Permission for anything, but is passed
            on to the guard function (if present).

        :arg action:
            [required]
            The name of action to check if user can perform.
            This should be a string matching the name of a registered permission.

        :arg klass:
            Optionally, the name of the class which the action is being performed on.
            This will usually need to be specified, but may not in some cases
            where the action being performed deals more with global state.

        :param item:
            Optionally, the exact instance of klass which action will be performed on.
            If not specified, permission will usually want to return ``True``
            if there exists at least 1 item for which the permission is true.

        :param attr:
            Optionally, the name of the attribute w/in the class
            which the action is being performed on.
            If not specified, it should be assumed action will be performed
            on any/all attributes of the object.

        :param scope:
            Optionally, in rare cases, the action requires a second object
            which represents the scope under which
            that it's acting upon, using the first, in the manner of a direct object.
            This kwd should be used in that case.
            For example, ``dict(action='Grant', klass='Role', item=role, scope=another_user)``
            describes the user attempting to grant a role to a specified user object.

        There is no requirement within the policy code as to the types
        used in "user", "klass", "attr", "item", or "scope",
        this is left up to the application. The suggested use is that
        "user", "item", "scope" should be objects,
        and "klass", "attr" should be strings.

        .. note::

            Only "user", "action", and "klass", "item" should ever be provided as positional arguments to this method.
        """
        #haven't decided the policy for these border cases,
        #so they're currently forbidden..
        if attr is False or attr == "":
            raise ValueError, "invalid attr: %r" % (attr,)
        if klass is False or klass == "":
            raise ValueError, "invalid klass: %r" % (klass,)
        #XXX: what if guard wants to accept custom kwds? would be issue for all other rules that don't match

        if action != self.action:
            return PERM.PENDING
        if self.klass is not None:
            if self.klass is False:
                if klass:
                    return PERM.PENDING
            elif self.klass is True:
                if not klass:
                    return PERM.PENDING
            elif self.klass != klass:
                return PERM.PENDING
        if self.attrs is not None and attr not in self.attrs:
            return PERM.PENDING
        if self.guard and _enable_guard:
            opts = dict()
            #TODO: could build a wrapper func inside __init__ time which takes care of this
            guard_kwds = self.guard_kwds
            if 'user' in guard_kwds:
                opts['user'] = user
            if 'action' in guard_kwds:
                opts['action'] = action
            if 'klass' in guard_kwds:
                opts['klass'] = klass
            if 'attr' in guard_kwds:
                opts['attr'] = attr
            if 'item' in guard_kwds:
                opts['item'] = item
            if 'scope' in guard_kwds:
                opts['scope'] = scope
            if 'perm' in guard_kwds:
                opts['perm'] = self
            #NOTE: not officially documented yet
            #should return one of True, False, or AccessDenied
            ##value = self.guard(**opts)
            ##if value in PERM.values:
            ##    return value
            ##if not value:
            ##    return PERM.PENDING
            if not self.guard(**opts):
                return PERM.PENDING
        if self.deny:
            return PERM.DENY
        else:
            return PERM.ALLOW

    def could_allow(self, action, klass=None, item=None, attr=None, scope=None):
        "check if permission could potentially be allowed"
        #NOTE: the fake-user & _enable_guard features are internal only, and subject to change.
        # use this function instead!
        result = self.check("fake-user", action, klass, item, attr, scope, _enable_guard=False)
        return (result == PERM.ALLOW)

    #=========================================================
    #helpers
    #=========================================================
    def __repr__(self):
        out = "Permission("
        if self.action:
            out += "action=%r, " % (self.action,)
        if self.klass is not None:
            out += "klass=%r, " % (self.klass,)
        if self.attrs:
            out += "attrs=%r, " % (list(self.attrs),)
        if self.guard:
            out += "guard=%r, " % (self.guard,)
        if self.deny:
            out += "deny=True, "
        if out[-1] != "(":
            out = out[:-2]
        return out + ")"

    def __eq__(self, other):
        if not hasattr(other, "check"):
            return False #not a perm object
        if self.action != other.action:
            return False
        if self.klass != other.klass:
            return False
        if self.attrs != other.attrs:
            return False
        if self.guard != other.guard:
            return False
        if self.deny != other.deny:
            return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)
    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#link - used by policy to track relationship of perms & roles
#=========================================================
class Link(BaseClass):
    """Defines link between permission objects and role objects."""
    perm_objs = None #list of permissions involved
    base_roles = None #set of roles explicitly linked to permissions
##    expanded_roles = None #set of roles which have permission (including inherited ones)

    def __init__(self, perm_objs, base_roles): ##, expanded_roles):
        self.perm_objs = perm_objs
        self.base_roles = base_roles
##        self.expanded_roles = expanded_roles

#=========================================================
#policy - base class for managing security
#=========================================================
class Policy(BaseClass):
    """This provided handling of security for a given context.

    Instance of this class contain a list of roles and permission mappings,
    and should be used as a frontend for managing permissions & roles
    for a given application.

    Main Methods
    ============
    The following are the main methods users of this class will need,
    listing roughly in the order they will need them:

    * :meth:`create_role` to add new roles to the policy
    * :meth:`permit` and :meth:`permit_list` to add new
      permissions and link them to previously created roles.
    * :meth:`freeze` to lock out changes, valid and prepare the policy for use.
    * :meth:`user_has_permission` to check if the user has
      permission to perform a given action.

    All other methods exposed by this class exist either
    to support the internal operation of the framework or to allow
    introspection of the existing policy by the application.

    Role Management
    ===============
    The following methods can be used to examine and alter
    the roles which the policy allows.

    .. automethod:: create_role

    .. automethod:: get_roles
    .. automethod:: has_role

    .. automethod:: get_user_roles
    .. automethod:: user_has_role
    .. automethod:: user_has_any_role

    .. automethod:: get_role_obj
    .. automethod:: get_role_objs

    Role Helpers
    ============
    The following methods are useful for manipulating
    sets of roles for various purposes:

    .. automethod:: expand_roles
    .. automethod:: collapse_roles
    .. automethod:: ascend_roles
    .. automethod:: descend_roles
    .. automethod:: ensure_valid_roles

    Permission Creation
    ===================
    The following methods can be used to create
    permission rules, and link them to roles:

    .. automethod:: permit
    .. automethod:: permit_list

    The following methods are used internally
    by permit and permit_list, and generally
    are not needed by external code:

    .. automethod:: create_permission
    .. automethod:: create_link

    Permission Examination
    ======================
    .. automethod:: user_has_permission

    The following methods are useful when examining
    the permissions, such as for displaying the permitted
    actions in a gui:

    .. automethod:: get_user_permissions
    .. automethod:: get_role_permissions
    .. automethod:: get_linked_roles

    Application Interface
    =====================
    Applications should overide the following methods
    either a kwd to the Policy class constructor,
    or by overriding the method via a subclass.

    .. automethod:: inspect_user_roles

    Policy Compilation
    ==================
    The following methods are related to locking
    out changes to the policy:

    .. automethod:: freeze
    .. attribute:: frozen

        This boolean attribute indicates whether
        the policy has been frozen or not.

    .. automethod:: ensure_frozen
    .. automethod:: ensure_thawed

    .. todo::
        flag to enable case-insensitive handling of role & klass names.
    """
    #=========================================================
    #class attrs
    #=========================================================

    #code should use these attrs when referencing Role or Permission classes,
    #allowing applications to override them by subclassing Policy.
    Role = Role
    Permission = Permission
    Link = Link

    #=========================================================
    #instance attrs
    #=========================================================
    _priority_in_use = False #set if any perm has non-zero priority
    _roles = None #dict mapping name of role -> Role object
    _links = None #list of link objects binding perms <-> roles
    _roleset_cache = None #cache of roleset -> perms derived from _links
    frozen = False #flag used to indicate policy has been frozen

##    rolesep = "," #separator used when parsing roles from string

    #=========================================================
    #init
    #=========================================================
    def __init__(self, inspect_user_roles=None):
        self._roles = {}
        self._links = []

        #override user access options
        if inspect_user_roles:
            self.inspect_user_roles = inspect_user_roles

    def freeze(self):
        """Compiles and validates security policy.

        This validates and initializes internal caches,
        and should be called after all roles and permissions
        have been added, but before policy is actually used.

        Once called, no more changes can be made to the policy.
        """
        self.ensure_thawed()
        self._freeze_links()
        self.frozen = True

    ##def thaw(self):
    ##    self.ensure_frozen()
    ##    self.frozen = False

    def ensure_frozen(self):
        "helper for methods that require policy is frozen"
        if not self.frozen:
            raise AssertionError, "this method can only be called AFTER the policy is frozen"
        return True

    def ensure_thawed(self):
        "helper for methods that require policy is not frozen"
        if self.frozen:
            raise AssertionError, "this method can only be called BEFORE the policy is frozen"
        return True

    #=========================================================
    #application interface
    #   all of these methods should be implemented by
    #   the application using the Policy object,
    #   with code specific to the application.
    #=========================================================
    #TODO: offer ability to translate class names -> classes,
    #   if defined, should act w/cache via weakref from inside Perm.check()

    def inspect_user_roles(self, user):
        """return names of all roles granted to a given user.

        The default implementation attempts to return
        the value of the ``roles`` attribute of any provided user object;
        thus this function should probably be overridden with an implementation
        which understands your application's user account system.
        You may override it by provided a replacement via
        ``Policy(inspect_user_roles=my_user_roles_func)``, or by subclassing Policy.

        .. note::
            Your implementation should *NOT* return roles which the user
            implicitly inherited from other roles, it should only return
            the roles they were explicitly granted.
        """
        return user.roles

    #=========================================================
    #role management
    #=========================================================

    #-------------------------------------------
    #role objects
    #-------------------------------------------
    def create_role(self, name, *args, **kwds):
        """create a new role and attach to Policy.

        ``name`` and all kwds are passed direclty to :class:`Role`;
        see it for a list of parameters.

        .. note::
            Policy enforces the restriction that any roles
            inherited by this one *must* be defined already.
        """
        self.ensure_thawed()
        role = self.Role(name, *args, **kwds)
        self._validate_role_obj(role)
##        role.policy = self
        self._roles[role.name] = role
        return role

    def _validate_role_obj(self, role):
        "validates role's inheritance chain before adding it"
        if self.has_role(role.name):
            raise KeyError, "A role with that name already exists: %r" % (role.name,)
        if role.inherits:
            if role.name in role.inherits:
                raise ValueError, "Role %r cannot inherit from itself" % (role.name,)
            self.ensure_valid_roles(role.inherits)

    def get_role_obj(self, role, default=Undef):
        "return :class:`Role` instance tied to name"
        if default is Undef:
            return self._roles[role]
        else:
            return self._roles.get(role,default)

    def get_role_objs(self, roles=None, grantable=None, rtype=set):
        "return all :class:`Role` instances in policy"
        if roles is None:
            result = self._roles.itervalues()
        else:
            result = (self.get_role_obj(r) for r in roles)
        if grantable is not None:
            result = (
                r
                for r in result
                if r.grantable == grantable
            )
        if rtype is iter:
            return result
        else:
            return rtype(result)

    #-------------------------------------------
    #role examination
    #-------------------------------------------
    def get_roles(self, grantable=None, rtype=set):
        """return all roles in policy, or for specified user.

        :param grantable:
            If ``True``, only grantable roles will be returned.
            If ``False``, only non-grantable roles will be returned.

        :param rtype:
            Alternate class to use for return type (eg: list, tuple),
            defaults to ``set``.
        """
        result = (
            r.name
            for r in self.get_role_objs(
                grantable=grantable, rtype=iter)
            )
        if rtype is iter:
            return result
        else:
            return rtype(result)

    def has_role(self, role, grantable=None, inherits=None):
        """check if role is defined in policy."""
        robj = self.get_role_obj(role,None)
        if robj is None:
            return False
        if grantable is not None and robj.grantable != grantable:
            return False
        if inherits and not self._inherits_from_role(role, inherits):
            return False
        return True

    def _inherits_from_role(self, role, parents):
        "check if role inherits from parent"
        if isstr(parents):
            parents = set([parents])
        get = self._roles.__getitem__
        stack = deque([role])
        while stack:
            role_obj = get(stack.pop())
            if role_obj.inherits:
                if intersects(role_obj.inherits, parents):
                    return True
                stack.extend(role_obj.inherits)
        return False

    #-------------------------------------------
    #user role queries
    #-------------------------------------------
    def get_user_roles(self, user, inherited=True, rtype=set):
        """returns set of roles granted to user.

        :param user: user to return roles for

        :param inherited:
            * ``True`` (the default): returns roles user was granted or inherited.
            * ``False``: returns only roles user was granted.

        :param rtype:
            This specifies an alternative return type,
            defaults to ``set``.

        :returns:
            set of roles granted to use
            (this is mainly a validating wrapper for :meth:`inspect_user_roles`).
        """
        roles = self.inspect_user_roles(user)
        self.ensure_valid_roles(roles, grantable=True)
        if inherited:
            return self.expand_roles(roles, rtype=rtype)
        elif hasattr(rtype, "__bases__") and isinstance(roles, rtype):
            return roles
        else:
            return rtype(roles)

    def user_has_role(self, user, role, inherited=True):
        """check if user has specified role.

        :arg user: the user to check against

        :type role: str
        :arg role: The role to check.

        :param inherited:
            * ``True`` (the default): consider roles user was granted or inherited.
            * ``False``: only consider roles user was granted.

        :returns:
            ``True`` if user had role, else ``False``.
        """
        assert self.ensure_valid_role(role)
        return role in self.get_user_roles(user, inherited=inherited)

    def user_has_any_role(self, user, roles, inherited=True):
        """check if user has *any* of the specified roles.

        :arg user: the user to check against

        :type roles: seq(str)
        :arg roles: the set of roles to check

        :param inherited:
            * ``True`` (the default): consider roles user was granted or inherited.
            * ``False``: only consider roles user was granted.

        :returns:
            ``True`` if any of the roles were held by user.
            ``False`` if none of them were.
        """
        assert self.ensure_valid_roles(roles)
        user_roles = self.get_user_roles(user, inherited=inherited)
        return intersects(user_roles, roles)

    #-------------------------------------------
    #role list filtering
    #-------------------------------------------
    def expand_roles(self, roles, rtype=set):
        """given list of roles, expand list to include inherited roles.

        :type roles: seq(str)
        :arg roles: sequence of role names

        :param rtype:
            Alternate class to use for return type (eg: list, tuple),
            defaults to ``set``.

        :returns:
            expanded set of role names which included all inherited roles.
        """
        #NOTE: expand_roles() is equivalent to descend_roles(keep=True),
        # but is slightly more efficient
        ##return self.descend_roles(roles, keep=True, rtype=rtype)
        target = set()
        add = target.add
        get = self._roles.__getitem__
        stack = deque(roles)
        while stack:
            name = stack.pop()
            if name not in target:
                add(name)
                role = get(name)
                if role.inherits:
                    stack.extend(role.inherits)
        if rtype is set:
            return target
        else:
            return rtype(target)

    def collapse_roles(self, roles, rtype=set):
        "inverse of expand_roles: removes any roles redundantly inherited from list"
        out = set(roles)
        inh = self.descend_roles(out)
        out.difference_update(inh)
        if rtype is set:
            return out
        else:
            return rtype(out)

    def ascend_roles(self, roles, keep=False, rtype=set):
        """return all roles which inherit from input set of roles"""
        #FIXME: this algorithm is very inefficient,
        # and could be rewriten to use something besides brute force
        #TODO: one improvment would be compiliation role_obj.inherited_by tree
        # once frozen (or just flushing cache when role altered)
        if keep:
            target = set(roles)
        else:
            target = set()
        stack = deque(roles)
        while stack:
            role = stack.pop()
            for role_obj in self.get_role_objs(rtype=iter):
                if role in role_obj.inherits:
                    target.add(role_obj.name)
                    stack.append(role_obj.name)
        if rtype is set:
            return target
        else:
            return rtype(target)

    def descend_roles(self, roles, keep=False, rtype=set):
        """return all roles which are inherited by input set of roles"""
        if keep:
            target = set(roles)
        else:
            target = set()
        get = self._roles.__getitem__
        stack = deque(roles)
        while stack:
            role = get(stack.pop())
            if role.inherits:
                target.update(role.inherits)
                stack.extend(role.inherits)
        if rtype is set:
            return target
        else:
            return rtype(target)

    #-------------------------------------------
    #role list validation
    #-------------------------------------------
    def ensure_valid_roles(self, roles, grantable=None):
        """validates that all provided roles exist, raising ValueError if they don't.

        :type roles: seq(str)
        :arg roles: roles to check

        :type grantable: bool|None
        :param grantable:
            * ``True``: raises ValueError if any of the roles *aren't* grantable.
            * ``False``: raises ValueError if any of the roles *are* grantable.
            * ``None`` (the default): grantable status is not checked.

        :returns:
            ``True`` if all roles pass.
            Raises ``ValueError`` if any of them fail.

        mainly useful for sanity checks and assert statements.
        """
        if isstr(roles):
            warn("Please use ensure_valid_role() for single role strings; this may be removed in the future")
            return self.ensure_valid_role(roles, grantable=grantable)
        missing = []
        badgrant = []
        for role in roles:
            robj = self.get_role_obj(role,None)
            if robj is None:
                missing.append(role)
                continue
            if grantable is not None and robj.grantable != grantable:
                badgrant.append(role)
        if missing:
            raise ValueError, "Unknown roles: %r" % (missing,)
        if badgrant:
            assert grantable is not None
            if grantable:
                raise ValueError, "Ungrantable roles: %r" % (badgrant,)
            else:
                raise ValueError, "Grantable roles: %r" % (badgrant,)
        return True

    def ensure_valid_role(self, role, grantable=None):
        """validates that roles exists, raising ValueError if it doesn't.

        :type roles: str
        :arg roles: role to check

        :type grantable: bool|None
        :param grantable:
            * ``True``: raises ValueError if the role *isn't* grantable.
            * ``False``: raises ValueError if the role *is* grantable.
            * ``None`` (the default): grantable status is not checked.

        :returns:
            ``True`` true if the role passes, raises ``ValueError`` on any failure.

        mainly useful for sanity checks and assert statements.
        """
        robj = self.get_role_obj(role,None)
        if robj is None:
            raise ValueError, "Unknown role: %r" % (role,)
        if grantable is not None and robj.grantable != grantable:
            if grantable:
                raise ValueError, "Role is not grantable: %r" % (role,)
            else:
                raise ValueError, "Role is grantable: %r" % (role,)
        return True

    #=========================================================
    #link & permission management
    #=========================================================
    def _norm_role_seq(self, roles):
        """helper which ensures ``roles`` is a sequence of roles.

        if ``roles`` is a sequence, returned unchanged.
        if ``roles`` is a string, converted to a list.
        """
        if isstr(roles):
            ##rs = self.rolesep
            ##if rs:
            ##    roles = split_condense(roles, rs, empty="strip")
            ##else:
                roles = [roles]
        return roles

    #--------------------------------------------------------
    #creation frontends
    #--------------------------------------------------------
    def permit(self, roles, action, klass=None, **kwds):
        """create & add new Permission object allowing the specified action.

        :type roles: str|seq of strs
        :arg roles:
            This can be either the name of a role (eg ``"admin"``),
            or a sequence of roles (eg ``["admin", "manager"]``).
            The user must possess at least one of these roles
            in order for the Permission object to be queried.

        :type action: str
        :arg action:
            The string specifying the action which his permission should match.
            This is passed to the :class:`Permission` constructor.

        :type klass: str|None|False
        :arg klass:
            Optional string specifying the class which this permission should match.
            This is passed to the :class:`Permission` constructor.

        :param \*\*kwds:
            All other keywords are passed directly to the the :class:`Permission` constructor.

        :returns:
            The resulting permission object,
            after having linked it to all the specified roles.
        """
        self.ensure_thawed()
        perm = self.create_permission(action, klass=klass, **kwds)
        self.create_link([perm], roles)
        return perm

    def permit_list(self, roles, perm_descs):
        """add multiple permissions at once.

        This function is the equivalent of calling
        :meth:`permit` with the same set of ``roles``
        for each dict in ``perm_desc``.

        :type roles: str|seq of strs
        :arg roles:
            This can be either the name of a role (eg ``"admin"``),
            or a sequence of roles (eg ``["admin", "manager"]``).
            The user must possess at least one of these roles
            in order for the Permission object to be queried.

        :type perm_desc: list of dicts
        :arg perm_descs:
            This should be a sequence of dictionaries,
            whose key/value pairs will be passed
            to the Permission constructor directly.

        :returns:
            list of the permission objects that were created,
            after having linked them to all the specified roles.
        """
        self.ensure_thawed()
        assert all('roles' not in perm for perm in perm_descs), "legacy syntax"
        perm_objs = [
            self.create_permission(**perm_desc)
            for perm_desc in perm_descs
        ]
        self.create_link(perm_objs, roles)
        return perm_objs

    #--------------------------------------------------------
    #creation backends
    #--------------------------------------------------------
    def create_permission(self, action, klass=None, **kwds):
        """create new Permission object, register with policy, and return it.

        :type action: str
        :arg action:
            The string specifying the action which his permission should match.
            This is passed to the :class:`Permission` constructor.

        :type klass: str|None|False
        :arg klass:
            Optional string specifying the class which this permission should match.
            This is passed to the :class:`Permission` constructor.

        :param \*\*kwds:
            All other keywords are passed directly to the the :class:`Permission` constructor.

        :rtype: Permission
        :returns:
            the resulting permission object

        .. note::
            The returned permission object will not be linked
            with any roles, to do that you must use :meth:`link_permissions`.
        """
        self.ensure_thawed()
        perm = self.Permission(action=action, klass=klass, **kwds)
##        perm.policy = self
        if perm.priority != 0 and not self._priority_in_use:
            log.debug("enabled priority sorting for permissions")
            self._priority_in_use = True
        return perm

    def create_link(self, perm_objs, roles):
        """add permissions objects to all specified roles.

        Once called, the user will be permitted to perform
        any action allowed by one of the ``perm_objs``,
        as long as the user has at least one of the given ``roles``.

        :arg perm_objs:
            list of permission objects.
        :arg roles:
            This can be either the name of a role (eg ``"admin"``),
            or a sequence of roles (eg ``["admin", "manager"]``).
            The user must possess at least one of these roles
            in order for the Permission object to be queried.

        .. note::
            This enforces the restriction that any roles referenced
            must be defined before this function is called.
        """
        self.ensure_thawed()
        roles = self._norm_role_seq(roles)
        self.ensure_valid_roles(roles)
        link = self.Link(perm_objs, frozenset(roles))
        self._links.append(link)

    #--------------------------------------------------------
    #link/perm examination
    #--------------------------------------------------------
    def get_user_permissions(self, user, rtype=tuple):
        "iterate through all perms belonging to user"
        #NOTE: we let iter_role_permissions expand roles,
        # since that way expand_roles() is also cached
        roles = self.get_user_roles(user, inherited=False)
        return self.get_role_permissions(roles, inherited=True, rtype=rtype)

    def get_role_permissions(self, roles, inherited=True, rtype=tuple):
        """return all permission objects attached to specified roles.

        This returns a list of all perm objs attached to any of the
        specified roles, in the order they should be checked to determine
        whether a specified actions is permitted.

        :type roles: str|seq(str)
        :arg roles: role or set of roles which should be checked.

        :param inherited:
            whether function should consider roles inherited
            from specified ``roles`` when searching for permission
            (defaults to True, rarely not needed).

        :param rtype:
            Though it defaults to ``list``,
            you can optionally specify the return type
            of this function, allowing for optimal conversion
            from the internal representation.
            Common values are ``tuple``, ``list``, ``set``,
            and ``iter``, the last one resulting in an iterator.

        :returns:
            The list (or other structure, per ``rtype`` param)
            containing all permission objects which were linked
            to 1 or more of the specified roles.
        """
        roles = frozenset(self._norm_role_seq(roles))
        if self.frozen:
            #if policy is frozen, cache the result before returning it
            key = (roles, inherited)
            cache = self._roleset_cache
            #XXX: make cache-disabling flag for testing?
            if key in cache:
                log.debug("iter_perm_objs: cache hit for %r", key)
                out = cache[key]
            else:
                log.debug("iter_perm_objs: cache miss for %r", key)
                out = cache[key] = self._get_role_permissions(roles, inherited)
        else:
            #if policy isn't frozen, perform the somewhat more expensive query each time.
            out = self._get_role_permissions(roles, inherited)
        assert isinstance(out,tuple)
        if rtype is tuple:
            return out
        else:
            return rtype(out)

    def _get_role_permissions(self, roles, inherited):
        "return list of perms; used by get_role_permissions()"
        if inherited:
            roles = self.expand_roles(roles)
        if hasattr(roles, "isdisjoint"): #py >= 26
            def test(link_roles):
                return not roles.isdisjoint(link_roles)
        else:
            def test(link_roles):
                return bool(roles.intersection(link_roles))
        out = [] #master list, in order
        for link in self._links:
            if test(link.base_roles):
                for perm in link.perm_objs:
                    if perm not in out:
                        out.append(perm)
        if self._priority_in_use:
            #sort list based on priority,
            #but otherwise preserving original order
            posmap = dict(
                (perm,idx)
                for idx,perm in enumerate(out)
            )
            def sk(perm):
                #make higher numbers sort first,
                #and perms w/ same priority keep original order
                return -perm.priority, posmap[perm]
            out = sorted(out, key=sk)
        return tuple(out)

    def get_linked_roles(self, perm_obj, inherited=True, limit_roles=None, rtype=set):
        "return set of all roles which are linked to a given perm_obj"
        #TODO: document this
        #NOTE: this just uses brute force to check everything,
        #  but since it's not called except during introspection,
        #  it doesn't really have to be very time-efficient.
        found = set()
        for link in self._links:
            if perm_obj in link.perm_objs:
                found.update(link.base_roles)
                if inherited:
                    found.update(self.ascend_roles(link.base_roles))
        if limit_roles is not None:
            found.intersection_update(limit_roles)
        if rtype is set:
            return found
        else:
            return rtype(found)

    #--------------------------------------------------------
    #finalize links
    #--------------------------------------------------------
    def _freeze_links(self):
        """finalize links policy."""
        #cache so we don't have to re-scan for the common pairs
        #this is main point of finalize(), since we'd have to purge
        #cache whenever something changed otherwise
        self._roleset_cache = {}

        #TODO: we could fill in link.expanded_roles now that role tree is frozen,
        #so that get_linked_roles() could run faster.

    #=========================================================
    #permission checking
    #=========================================================
    def user_has_permission(self, user, action,
                            klass=None, item=None, **kwds):
        """check if user has permission for a specific action.

        This runs through all :class:`Permission` instances
        within the policy which are linked to any of the roles
        possessed by the user. If any of them make a definitive statement
        about the :ref:`permission question <permission-question>` being asked,
        the result (``True`` or ``False``) will be returned.
        If no match is found, the default is to return ``False``.
        """
        perm_objs = self.get_user_permissions(user, rtype=iter)
        return self._check_permissions(perm_objs, user, action, klass, item, **kwds)
    #XXX: rename/provide alias named "check()" to match Permission?
        
    def _check_permissions(self, perm_objs, user, action,
                           klass=None, item=None, **kwds):
        """check query against a list of permission objects.

        :param perm_obj:
            sequence or iterator containing permission objects to check in order

        :returns:
            ``True`` if permitted, ``False`` if denied, ``None`` if neither
            permitted or denied (should usually be treated like Denied).
        """
        for perm_obj in perm_objs:
            result = perm_obj.check(user, action, klass, item, **kwds)
            if result == PERM.ALLOW:
                return True
            if result == PERM.DENY:
                return False
            assert result == PERM.PENDING
        return None

    def could_allow(self, action, klass=None, item=None, **kwds):
        """check if policy could even *potentially* allow a permission to pass for some role.
        
        this disables all guards, looks at all permissions attached to all roles,
        and returns true if there exists some combination of roles
        which potentially could permit a to gain this permission.
        """
        #NOTE: this bypasses internal links database caching,
        #since it's faster to just scan everything.
        #XXX: we could cache the results of *this* func
        seen = set()
        for link in self._links:
            for perm in link.perm_objs:
                if perm not in seen:
                    if perm.could_allow(action, klass, item, **kwds):
                        return True
                    seen.add(perm)
        return False
        
    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#helpers
#=========================================================
class UserPermSummary(BaseClass):
    """This is a helper which tries to summarize the permissions a user has,
    ordered in a manner suitable for handing to a pretty-printer.

    .. warning::

        This is an experimental class, not listed in the main documentation,
        which may be removed / altered without warning.

    It's implemented as a class which can be iterated over to
    yeild ``(perm_obj,roles)`` pairs, where
    each ``perm_obj`` is one which the user has been granted,
    and ``roles`` are all the roles which the user has which link to that permission
    """
    #=========================================================
    #attrs
    #=========================================================

    #filled in by constructor
    policy = None
    user = None

    #optionally overridden by constructor
    ordered_actions = ()
    ordered_roles = ()
    sort_perms = True

    #filled in by prepare()
    all_roles = None
    user_roles = None
    granted_user_roles = None
    inherited_user_roles = None
    user_perms = None

    #=========================================================
    #init
    #=========================================================
    def __init__(self, policy, user,
                 ordered_actions=None, ordered_roles=None,
                 sort_perms=None,
                 ):
        self.policy = policy
        self.user = user
        if ordered_actions is None:
            ordered_actions = self.ordered_actions
        self.ordered_actions = list(ordered_actions)
        if ordered_roles is None:
            ordered_roles = self.ordered_roles
        self.ordered_roles = list(ordered_roles)
        if sort_perms is not None:
            self.sort_perms = sort_perms
        self.prepare()

    def prepare(self):
        "prepare all lists for the iterator and program to access"
        policy, user = self.policy, self.user
        self.all_roles = sorted(policy.get_roles(rtype=iter), key=self.sk_role)
        self.user_roles = sorted(policy.get_user_roles(user,rtype=iter), key=self.sk_role)
        self.granted_user_roles = sorted(policy.get_user_roles(user,rtype=iter,inherited=False), key=self.sk_role)
        self.inherited_user_roles = sorted(set(self.user_roles).difference(self.granted_user_roles), key=self.sk_role)
        if self.sort_perms:
            self.user_perms = sorted(policy.get_user_permissions(user,rtype=iter), key=self.sk_perm_obj)
        else:
            self.user_perms = policy.get_user_permissions(user,rtype=list)

    def get_linked_roles(self, perm_obj):
        "returns all user's granted roles which gave them this permission, returned pre-sorted"
        itr = self.policy.get_linked_roles(perm_obj, inherited=False, rtype=iter, limit_roles=self.user_roles)
        return sorted(itr, key=self.sk_role)

    #=========================================================
    #sort key functions
    #=========================================================
    def sk_string(self, value):
        "func to generate sort key for ordering strings (eg action and klass)"
        if isstr(value):
            return condense(value, " -+.").lower(), value
        else:
            return value

    def sk_role(self, role):
        "func to generate sort key for ordering roles"
        #TODO: could probably factor out index code into sk_from_index(source,value)
        #TODO: default sort after ordered roles should be via ordering of reverse hierarchy, tallest first
        try:
            return self.ordered_roles.index(role), self.sk_string(role)
        except ValueError:
            return len(self.ordered_roles), self.sk_string(role)

    def sk_granted_role(self, role):
        "func to generate sort key for ordering roles, with addition that granted roles are listed first"
        try:
            return self.granted_user_roles.index(role), self.sk_role(role)
        except ValueError:
            return len(self.granted_user_roles), self.sk_role(role)

    def sk_perm_obj(self, perm_obj):
        "func to generate sort key for ordering permissions"
        try:
            ci = self.ordered_actions.index(perm_obj.action)
        except ValueError:
            ci = len(self.ordered_actions)
        return self.sk_string(perm_obj.klass), ci, self.sk_string(perm_obj.action), self.get_linked_roles(perm_obj)

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#eoc
#=========================================================
