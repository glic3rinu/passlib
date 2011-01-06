"""bps.security.policy unitests"""

#=========================================================
#imports
#=========================================================
#core
from __future__ import with_statement
import warnings
#site
#pkg
from bps import *
from bps.types import stub
from bps.meta import is_iter
from bps.tests.utils import TestCase, catch_all_warnings
from bps.security.policy import Policy, Role, Permission, PERM

#=========================================================
#helpers
#=========================================================
def policy_01x(**kwds):
    "default roleset used by many tests"
    #NOTE: this is a non-sensical inheritance hierarchy,
    #which mainly exists to provide a variety of shapes for testing purposes.
    # admin -> (user, pirate) -> base
    policy = Policy(**kwds)
    b = policy.create_role("base", grantable=False)
    u = policy.create_role("user", "base")
    p = policy.create_role("pirate", "base")
    a = policy.create_role("admin", 'user,pirate')
    return policy,b,u,p,a

def policy_01(**kwds):
    return policy_01x(**kwds)[0]

def policy_02x():
    "default roleset+permset used by many tests"
    #NOTE: this is a non-sensical set of permissions,
    #which mainly exists to provide a perms for testing purposes
    policy = policy_01()
    a = policy.permit("admin", "perm-a")
    b = policy.permit("base", "perm-b")
    u = policy.permit("user", "perm-u")
    p = policy.permit("pirate", "perm-p")
    policy.freeze()
    #NOTE: order should be order of definition
    return policy,a,b,u,p

def policy_02():
    return policy_02x()[0]

def policy_03x():
    "example roleset+permset"
    #NOTE: this role & permset should make sense,
    # and are a stripped down version of the policy for a web application.

    policy = Policy()

    #
    #create a nice user account object
    #
    class User(BaseClass):
        policy = None

        def __init__(self, name=None, roles=None):
            self.name = name or "NoName"
            self.roles = roles or ()

        def has_role(self, role):
            #NOTE: by calling this instead of reading .roles, we get benefit of inherited role system
            return self.policy.user_has_role(self,role)

        def has_permission(self, *a, **k):
            return self.policy.user_has_permission(self, *a, **k)
    User.policy = policy

    #
    #create roles
    #
    policy.create_role("person", desc="base role for all users")
    policy.create_role("client", inherits="person", desc="role for end users of system")
    policy.create_role("employee", inherits="person", desc="role for people running system")
    policy.create_role("admin", inherits="employee", desc="system administrator")

    #
    #create some helpful guard funcs
    #
    def is_own_account(user, item=None):
        "only permit action if it's on user's own account"
        if item:
            return user == item
        return True

    def is_client_account(user, item=None):
        "only permit action if it's on a client user account"
        if item:
            return item.has_role("client")
        return True

    #
    #grant actions to roles
    #

    #all users can edit own account, and log in
    policy.permit_list(["person"],[
        dict(action="sign-in", klass=False),
        dict(action="view", klass="user", guard=is_own_account),
        dict(action="update", klass="user", guard=is_own_account),
        ])

    #all clients can manage their journal entries
    #NOTE: in real-world, a guard would be used to
    # require journal was owned by user:
    ##def is_own_journal(user, item=None):
    ##    if item:
    ##        return item.owner == user
    ##    return True
    policy.permit_list(["client"],[
        dict(action="list", klass="journal"),
        dict(action="create", klass="journal"),
        dict(action="view", klass="journal"),
        dict(action="update", klass="journal", attrs=("owner",), deny=True),
        dict(action="update", klass="journal"),
        dict(action="retire", klass="journal"),
    ])

    #all employees can manage client accounts
    policy.permit_list(["employee"],[
        dict(action="list", klass="user", guard=is_client_account),
        dict(action="create", klass="user", guard=is_client_account),
        dict(action="view", klass="user", guard=is_client_account),
        dict(action="update", klass="user", guard=is_client_account),
        dict(action="retire", klass="user", guard=is_client_account),
        ])

    #and admins can perform all std actions on any class
    policy.permit_list(["admin"],[
        dict(action="list", klass=True),
        dict(action="create", klass=True),
        dict(action="view", klass=True),
        dict(action="update", klass=True),
        dict(action="retire", klass=True),
        dict(action="delete", klass=True), #and only admins can delete things forever
        ])

    #
    #freeze policy & create some users
    #
    policy.freeze()
    admin = User(roles=("admin",))
    employee = User(roles=("employee",))
    client = User(roles=("client",))
    return policy, admin, employee, client, User

#TODO: remove this stub
def check_rtype(self, func, deftype, elems, ordered=False):
    "run test for func with rtype return"
    return self.check_function_rtype(func, retval=elems, rtype=deftype, ordered=ordered)

#=========================================================
#support classes
#=========================================================
class RoleClassTest(TestCase):
    "test role class itself"

    def test_const_basic(self):
        "test basic role constructor"
        r = Role("admin")
        self.assertEquals(r.name, "admin")
        self.assertEquals(r.title, "Admin")
        self.assertIs(r.desc, None)
        self.assertEquals(r.inherits, frozenset())
        self.assertEquals(r.grantable, True)

    def test_const_invalid(self):
        "test invalid role constructors"
        self.assertRaises(TypeError, Role)
        self.assertRaises(TypeError, Role, "admin", xxx=123)

    def test_const_full(self):
        "test common role constructor"
        r = Role("admin", title="captain", inherits=["user", "pirate", "user"],
                 desc="descy", grantable=False)
        self.assertEquals(r.name, "admin")
        self.assertEquals(r.title, "captain")
        self.assertEquals(r.desc, "descy")
        self.assertEquals(r.grantable, False)
        self.assertEquals(r.inherits, frozenset(["user", "pirate"]))

    def test_eq(self):
        "test role equal to itself"

        r1 = Role("admin")
        self.assertEquals(r1,r1)

        r2 = Role("other")
        self.assertNotEquals(r1,r2)

        #NOTE: module doesn't current assert either way on this,
        # an eq operator may be defined in the future.
        # this test is just to ensure current behavior is reliable.
        r3 = Role("admin")
        self.assertNotEquals(r1,r3)

class PermissionClassTest(TestCase):
    "test permission class itself"

    #=========================================================
    #constructors
    #=========================================================
    def test_const_basic(self):
        "test basic perm constructor"
        p = Permission("sign-in")
        self.assertEquals(p.action, "sign-in")
        self.assertEquals(p.desc, None)
        self.assertEquals(p.klass, None)
        self.assertEquals(p.attrs, None)
        self.assertEquals(p.guard, None)
        self.assertEquals(p.deny, False)
        self.assertEquals(p.priority, 0)

    def test_const_invalid(self):
        "test invalid perm constructors"

        #make sure action is required
        self.assertRaises(TypeError, Permission)
        self.assertRaises(TypeError, Permission, klass=False)

        #make sure unknowns raise err
        self.assertRaises(TypeError, Permission, "sign-in", xxx=123)

    def test_const_full(self):
        "test full perm constructor"
        def g(user):
            return True
        p = Permission(
            action="update",
            klass="user",
            attrs=("bob","sue"),
            guard=g,
            deny=True,
            desc="desc",
            priority=-100,
        )
        self.assertEquals(p.action, "update")
        self.assertEquals(p.desc, "desc")
        self.assertEquals(p.klass, "user")
        self.assertEquals(p.attrs, frozenset(["bob", "sue"]))
        self.assertEquals(p.guard, g)
        self.assertEquals(p.guard_kwds, frozenset(["user"]))
        self.assertEquals(p.deny, True)
        self.assertEquals(p.priority, -100)

    #=========================================================
    #check() basic usage
    #=========================================================
    def test_check_params(self):
        "test check() params"
        u = stub()
        p = Permission("update", "user", attrs=("bob", None))

        self.assertEquals(p.check(u,"update","user",u, attr=None), PERM.ALLOW)
        self.assertEquals(p.check(u,"update","journal",u, attr=None), PERM.PENDING)

        p = Permission("sign-in", False)
        self.assertEquals(p.check(u,"sign-in"), PERM.ALLOW)
        self.assertEquals(p.check(u,"sign-in",None), PERM.ALLOW)
        self.assertEquals(p.check(u,"sign-in","user"), PERM.PENDING)

    def test_check_invalid_values(self):
        "test passing invalid values to check"
        u = stub()
        p = Permission("update")

        #haven't decided the policy for these border cases,
        #so they're currently forbidden..
        self.assertRaises(ValueError, p.check, u, "update", attr="")
        self.assertRaises(ValueError, p.check, u, "update", attr=False)
        self.assertRaises(ValueError, p.check, u, "update", klass="")
        self.assertRaises(ValueError, p.check, u, "update", klass=False)

    #=========================================================
    #could_allow() basic usage
    #=========================================================
    def test_could_allow_params(self):
        #simple check against action + klass
        p = Permission("update", "user", attrs=("bob", None))
        self.assert_(p.could_allow("update","user", attr=None))
        self.assert_(not p.could_allow("update","journal", attr=None))

        #simple check against action - klass
        p = Permission("sign-in", False)
        self.assert_(p.could_allow("sign-in"))
        self.assert_(p.could_allow("sign-in",None))
        self.assert_(not p.could_allow("sign-in","user"))
   
    def test_could_allow_guard(self):
        #simple check that guard is ignored
        p = Permission("update", "user", guard=lambda user: False)
        self.assert_(p.could_allow("update","user"))
        self.assert_(not p.could_allow("update","journal"))
    
    #=========================================================
    #action matching
    #=========================================================
    def test_action(self):
        "test generic action specifier"
        u = stub()
        p = Permission("update")
        self.assertEquals(p.check(u, None), PERM.PENDING)
        self.assertEquals(p.check(u, "update"), PERM.ALLOW)
        self.assertEquals(p.check(u, "zzz"), PERM.PENDING)

    #=========================================================
    #klass matching
    #=========================================================
    #NOTE: klass="" and klass=False shouldn't be passed into check normally,
    # only pass in a non-empty string or None.

    def test_klass_false(self):
        "test klass=False matches only if klass missing"
        u = stub()
        p = Permission("sign-in", klass=False)
        self.assertEquals(p.klass, False)

        self.assertEquals(p.check(u,"sign-in"), PERM.ALLOW)
        self.assertEquals(p.check(u,"sign-in",None), PERM.ALLOW)
        self.assertEquals(p.check(u,"sign-in","user"), PERM.PENDING)
        self.assertEquals(p.check(u,"sign-in","journal"), PERM.PENDING)

    def test_klass_none(self):
        "test klass=None matches anything"
        u = stub()

        p1 = Permission("sign-in")
        self.assertEquals(p1.klass, None)

        p = Permission("sign-in", klass=None)
        self.assertEquals(p.klass, None)

        self.assertEquals(p.check(u,"sign-in"), PERM.ALLOW)
        self.assertEquals(p.check(u,"sign-in",None), PERM.ALLOW)
        self.assertEquals(p.check(u,"sign-in","user"), PERM.ALLOW)
        self.assertEquals(p.check(u,"sign-in","journal"), PERM.ALLOW)

    def test_klass_true(self):
        "test klass=True matches anything except missing klass"
        u = stub()

        p = Permission("sign-in", klass=True)
        self.assertEquals(p.klass, True)

        self.assertEquals(p.check(u,"sign-in"), PERM.PENDING)
        self.assertEquals(p.check(u,"sign-in",None), PERM.PENDING)
        self.assertEquals(p.check(u,"sign-in","user"), PERM.ALLOW)
        self.assertEquals(p.check(u,"sign-in","journal"), PERM.ALLOW)

    def test_klass_exact(self):
        "test klass=<str> matches only that string"
        u = stub()

        p = Permission("sign-in", klass="user")
        self.assertEquals(p.klass, "user")

        self.assertEquals(p.check(u,"sign-in"), PERM.PENDING)
        self.assertEquals(p.check(u,"sign-in",None), PERM.PENDING)
        self.assertEquals(p.check(u,"sign-in","user"), PERM.ALLOW)
        self.assertEquals(p.check(u,"sign-in","journal"), PERM.PENDING)

    #=========================================================
    #attr matching
    #=========================================================
    #NOTE: no policy is current set for attr="" and attr=False,
    # these shouldn't be used.

    def test_attrs_none(self):
        "test attrs=None matches any/no attrs"
        u = stub()

        p1 = Permission("update")
        self.assertEquals(p1.attrs, None)

        p = Permission("update", attrs=None)
        self.assertEquals(p.attrs, None)

        self.assertEquals(p.check(u,"update"), PERM.ALLOW)
        self.assertEquals(p.check(u,"update", attr=None), PERM.ALLOW)
        self.assertEquals(p.check(u,"update", attr="xxx"), PERM.ALLOW)
        self.assertEquals(p.check(u,"update", attr="zzz"), PERM.ALLOW)

    def test_attrs_empty(self):
        "test attrs=(), attrs=(None), and attrs=False matches no attr"
        u = stub()

        p1 = Permission("update", attrs=False)
        self.assertEquals(p1.attrs, frozenset([None]))

        p1 = Permission("update", attrs=(None,))
        self.assertEquals(p1.attrs, frozenset([None]))

        p = Permission("update", attrs=())
        self.assertEquals(p.attrs, frozenset([None]))

        self.assertEquals(p.check(u,"update"), PERM.ALLOW)
        self.assertEquals(p.check(u,"update", attr=None), PERM.ALLOW)
        self.assertEquals(p.check(u,"update", attr="xxx"), PERM.PENDING)
        self.assertEquals(p.check(u,"update", attr="zzz"), PERM.PENDING)

    def test_attrs_explicit(self):
        "test attrs=('a','b') matches only those attrs"
        u = stub()

        p = Permission("update", attrs=("xxx", "yyy","xxx"))
        self.assertEquals(p.attrs, frozenset(["xxx", "yyy"]))

        self.assertEquals(p.check(u,"update"), PERM.PENDING)
        self.assertEquals(p.check(u,"update", attr=None), PERM.PENDING)
        self.assertEquals(p.check(u,"update", attr="xxx"), PERM.ALLOW)
        self.assertEquals(p.check(u,"update", attr="zzz"), PERM.PENDING)

    def test_attrs_explicit2(self):
        "test attrs=('a','b',None) matches only those or no attrs"
        u = stub()

        p = Permission("update", attrs=("xxx", "yyy",None))
        self.assertEquals(p.attrs, frozenset(["xxx", "yyy",None]))

        self.assertEquals(p.check(u,"update"), PERM.ALLOW)
        self.assertEquals(p.check(u,"update", attr=None), PERM.ALLOW)
        self.assertEquals(p.check(u,"update", attr="xxx"), PERM.ALLOW)
        self.assertEquals(p.check(u,"update", attr="zzz"), PERM.PENDING)

    #=========================================================
    #guard matching
    #=========================================================
    result = None #used as temp location for some guards in these tests

    def test_guard_retval(self):
        "test guard w/o args, using diff retvals"

        #test True return value
        def g():
            self.result = True
            return True
        u = stub()
        p = Permission("update", guard=g)
        self.result = False
        self.assertEquals(p.check(u,"update"), PERM.ALLOW)
        self.assert_(self.result)

        #test False return value
        def g():
            self.result = True
            return False
        u = stub()
        p = Permission("update", guard=g)
        self.result = False
        self.assertEquals(p.check(u,"update"), PERM.PENDING)
        self.assert_(self.result)

        #test None return value
        def g():
            self.result = True
            return None
        u = stub()
        p = Permission("update", guard=g)
        self.result = False
        self.assertEquals(p.check(u,"update"), PERM.PENDING)
        self.assert_(self.result)

        #test false-as-bool return value
        def g():
            self.result = True
            return ""
        u = stub()
        p = Permission("update", guard=g)
        self.result = False
        self.assertEquals(p.check(u,"update"), PERM.PENDING)
        self.assert_(self.result)

        #test true-as-bool return value
        def g():
            self.result = True
            return "xxx"
        u = stub()
        p = Permission("update", guard=g)
        self.result = False
        self.assertEquals(p.check(u,"update"), PERM.ALLOW)
        self.assert_(self.result)

    def test_guard_after_patterns(self):
        "test guard called after patterns"
        def g():
            self.result = True
            return True
        u = stub()

        #check action
        self.result = False
        p = Permission("update", guard=g)
        self.assertEquals(p.check(u,"list"),PERM.PENDING)
        self.assert_(not self.result)
        self.assertEquals(p.check(u,"update"),PERM.ALLOW)
        self.assert_(self.result)

        #check klass
        self.result = False
        p = Permission("update", "user", guard=g)
        self.assertEquals(p.check(u,"update", "journal"),PERM.PENDING)
        self.assert_(not self.result)
        self.assertEquals(p.check(u,"update", "user"),PERM.ALLOW)
        self.assert_(self.result)

        #check attrs
        self.result = False
        p = Permission("update", attrs=["x"], guard=g)
        self.assertEquals(p.check(u,"update", attr="y"),PERM.PENDING)
        self.assert_(not self.result)
        self.assertEquals(p.check(u,"update", attr="x"),PERM.ALLOW)
        self.assert_(self.result)

    def test_guard_wildcard(self):
        "test guard w/ all kwds defaulting"
        def g(**kwds):
            self.result = kwds
            return True
        u = stub()
        p = Permission("update", guard=g)
        self.result = False
        self.assertEquals(p.check(u,"update"), PERM.ALLOW)
        self.assertEquals(self.result,dict(
            user=u,
            action="update",
            klass=None,
            attr=None,
            item=None,
            scope=None,
            perm=p,
            ))

    def test_guard_full(self):
        "test guard w/ all kwds filled in"
        def g(**kwds):
            self.result = kwds
            return True
        u = stub()
        p = Permission("update", guard=g)
        self.result = False
        self.assertEquals(p.check(u,"update","user",u,attr="xxx",scope=self), PERM.ALLOW)
        self.assertEquals(self.result,dict(
            user=u,
            action="update",
            klass="user",
            attr="xxx",
            item=u,
            scope=self,
            perm=p,
            ))

    def test_guard_some(self):
        "test guard w/ all kwds filled in but few used"
        def g(user, action=None, item=None):
            self.result = dict(user=user, action=action, item=item)
            return True
        u = stub()
        p = Permission("update", guard=g)
        self.result = False
        self.assertEquals(p.check(u,"update","user",u,attr="xxx",scope=self), PERM.ALLOW)
        self.assertEquals(self.result,dict(
            user=u,
            action="update",
            item=u,
            ))

    #=========================================================
    #test eq
    #=========================================================
    def test_eq(self):
        "test permission equality operator works"

        #test match considers action, klass, attrs, guard, deny
        for k,a,b in (
            ("action", "update", "delete"),
            ("klass", None, False),
            ("klass", "user", False),
            ("klass", "user", "journal"),
            ("attrs", ("xxx",), ("yyy",)),
            ("attrs", (), ("yyy",)),
            ("guard", lambda : True, lambda : True),
            ("deny", True, False),
        ):
            ad = {k:a}
            bd = {k:b}
            if k != "action":
                ad["action"] = bd["action"] = "update"
            p1 = Permission(**ad)
            p2 = Permission(**ad)
            p3 = Permission(**bd)
            self.assertEquals(p1,p2)
            self.assertEquals(p1,p1)
            self.assertNotEquals(p1,p3)
            self.assertNotEquals(p2,p3)

        #test match discards non-perms
        p = Permission("update")
        self.assertNotEquals(p, None)
        self.assertNotEquals(p, "xxx")
        self.assertNotEquals(p, Role("admin"))

        #test match ignores desc
        p1 = Permission("update", desc="xxx")
        p2 = Permission("update", desc="yyy")
        self.assertEquals(p1,p1)
        self.assertEquals(p1,p2)

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#
#=========================================================
class RoleManagementTest(TestCase):
    "test policy's role management functions"

    #=========================================================
    #test create_role(name, *a, **k) -> role_obj
    #=========================================================
    def test_create_role_simple(self):
        "test creating a role works properly"
        policy = Policy()

        r = policy.create_role("admin")
        self.assertIsInstance(r, Role)
        self.assertEquals(r.name, "admin")
        self.assertEquals(r.title, "Admin")
        self.assertEquals(r.inherits, frozenset())

        self.assertElementsEqual(policy.get_role_objs(), [r])

    def test_create_role_inherits(self):
        "test role inheritance works properly"
        policy = Policy()

        u = policy.create_role("pirate")
        p = policy.create_role("user")

        r = policy.create_role("admin", inherits=["user", "pirate", "user"])
        self.assertEquals(r.name, "admin")
        self.assertEquals(r.inherits, frozenset(["user", "pirate"]))

        self.assertElementsEqual(policy.get_role_objs(), [u,p,r])

    def test_create_role_inherits_undefined(self):
        "test role inheritance requires existing parents"
        policy = Policy()

        #shouldn't be able to create role w/ out parents
        self.assertRaises(ValueError, policy.create_role, "admin", ["user", "pirate"])
        #KeyError: undefined roles: user, pirate

        u = policy.create_role("user")

        #without _all_ parents
        self.assertRaises(ValueError, policy.create_role, "admin", ["user", "pirate"])
        #KeyError: undefined roles: pirate

        self.assertElementsEqual(policy.get_role_objs(), [u])

    def test_create_role_inherit_self(self):
        "test role can't inherit from self"
        policy = Policy()

        self.assertRaises(ValueError, policy.create_role, "user", ['user'])
        #ValueError: role can't inherit from self

    def test_create_role_frozen(self):
        "test role can't be created after frozen"
        policy = Policy()
        policy.freeze()

        self.assertRaises(AssertionError, policy.create_role, "user")
        #AssertionError: policy frozen

    def test_create_role_subclassed(self):
        "test create_role() honors Policy.Role"
        #make sure orig Role won't take "xxx"
        self.assertRaises(TypeError, Policy.Role, "test", xxx=23)

        #create role subclass which accepts "xxx"
        class MyRole(Policy.Role):
            def __init__(self, *a, **k):
                self.xxx = k.pop("xxx",None)
                self.__super.__init__(*a,**k)

        #create policy class which uses MyRole
        class MyPolicy(Policy):
            Role = MyRole

        #try creating role, make sure MyRole was used
        policy = MyPolicy()
        r = policy.create_role("test", xxx=23)
        self.assertIsInstance(r,MyRole)
        self.assertEqual(r.xxx, 23)

    #=========================================================
    #test get_role_obj(name, default=Undef) -> role_obj|default/Error
    #=========================================================
    def test_get_role_obj(self):
        policy = Policy()

        #check raises error by default
        self.assertRaises(KeyError, policy.get_role_obj, "user")

        #test default works
        self.assertIs(policy.get_role_obj("user",None), None)

        #test returns correct result
        u = policy.create_role("user")
        self.assertIs(policy.get_role_obj("user"), u)

    #=========================================================
    #test get_role_objs(roles=None, grantable=None, rtype=set)-> role_objs
    #=========================================================
    def test_gro_plain(self):
        "test get_role_objs() w/o args"
        policy,b,u,p,a = policy_01x()
        result = policy.get_role_objs()
        self.assertElementsEqual(result, [b,u,p,a])

    def test_gro_roles(self):
        "test get_role_objs() with role name filter"
        policy,b,u,p,a = policy_01x()

        #check normal
        result = policy.get_role_objs(['admin','pirate'])
        self.assertElementsEqual(result,[a,p])

        #check w/ unknown
        self.assertRaises(KeyError, policy.get_role_objs, ['admin', 'person'])

        #check ordering matches input list
        result = policy.get_role_objs(["admin","base","user","pirate"],
            rtype=list)
        self.assertEquals(result,[a,b,u,p])

        #check ordering matches input list (just in case 1st was accident)
        result = policy.get_role_objs(["base","user","admin","pirate"],
            rtype=list)
        self.assertEquals(result,[b,u,a,p])

    def test_gro_grantable(self):
        "test get_role_objs() with grantable filter"
        policy,b,u,p,a = policy_01x()
        self.assertElementsEqual(policy.get_role_objs(grantable=None),[b,u,p,a])
        self.assertElementsEqual(policy.get_role_objs(grantable=True),[u,p,a])
        self.assertElementsEqual(policy.get_role_objs(grantable=False),[b])

    def test_gro_grantable_roles(self):
        "test get_role_objs() with grantable & role name filters"
        policy,b,u,p,a = policy_01x()
        self.assert_sets_equal(
            policy.get_role_objs(['admin','base'], grantable=True),
            [a])
        self.assert_sets_equal(
            policy.get_role_objs(['admin','base'], grantable=False),
            [b])

    def test_gro_rtype(self):
        "test get_role_objs() rtype option"
        policy,b,u,p,a = policy_01x()
        elems = [b,u,p,a]
        check_rtype(self, policy.get_role_objs, set, elems)

        func = partial(policy.get_role_objs, ["base","user","pirate","admin"])
        check_rtype(self, func, set, elems, ordered=True)

    #=========================================================
    #test get_roles(grantable=None, rtype=set)
    #=========================================================
    def test_gr_plain(self):
        "test get_roles() w/o args"
        policy = policy_01()
        result = policy.get_roles()
        self.assert_sets_equal(result, ["base", "admin", "user", "pirate"])

    def test_gr_grantable(self):
        "test get_roles() with grantable filter"
        policy = policy_01()
        self.assertElementsEqual(
            policy.get_roles(grantable=None),
            ["base","admin","user","pirate"])
        self.assertElementsEqual(
            policy.get_roles(grantable=True),
            ["admin","user","pirate"])
        self.assertElementsEqual(
            policy.get_roles(grantable=False),
            ["base"])

    def test_gr_rtype(self):
        "test get_roles() rtype option"
        policy = policy_01()
        elems = ["base", "user", "pirate", "admin"]
        out = policy.get_roles(rtype=list)
        self.assert_sets_equal(out,elems)
        check_rtype(self, policy.get_roles, set, out, ordered=True)

    #=========================================================
    #test has_role(role, grantable=None)
    #=========================================================
    def test_has_role(self):
        "test has_role()"
        policy = policy_01()

        #test grantable role
        self.assert_(policy.has_role("admin"))
        self.assert_(policy.has_role("admin", grantable=True))
        self.assert_(not policy.has_role("admin", grantable=False))

        #test ungrantable role
        self.assert_(policy.has_role("base"))
        self.assert_(not policy.has_role("base", grantable=True))
        self.assert_(policy.has_role("base", grantable=False))

        #test unknown role
        self.assert_(not policy.has_role("fooey"))
        self.assert_(not policy.has_role("fooey", grantable=True))
        self.assert_(not policy.has_role("fooey", grantable=False))

    def test_has_role_inherits(self):
        "test has_role() inherits kwd"
        policy = policy_01()

        self.assertEqual(policy.has_role("admin", inherits="base"), True)
        self.assertEqual(policy.has_role("admin", inherits="pirate"), True)
        self.assertEqual(policy.has_role("admin", inherits=["user", "base"]), True)

        self.assertEqual(policy.has_role("user", inherits="base"), True)
        self.assertEqual(policy.has_role("user", inherits="pirate"), False)
        self.assertEqual(policy.has_role("user", inherits=["admin", "base"]), True)

        #make sure can't inherit from self
        self.assertEqual(policy.has_role("user", inherits="user"), False)

        #or from child
        self.assertEqual(policy.has_role("user", inherits="admin"), False)

    #=========================================================
    #test get_user_roles(user, inherited=True, rtype=set)
    #=========================================================
    def test_gur_simple(self):
        "test basic get_user_roles behavior"
        policy = policy_01()
        user = stub(roles=("user",))

        self.assert_sets_equal(
            policy.get_user_roles(user),
            ['user','base'],
        )

        self.assert_sets_equal(
            policy.get_user_roles(user, inherited=False),
            ['user',],
        )

    def test_gur_rtype(self):
        "test get_user_roles() rtype"
        policy = policy_01()
        user = stub(roles=("user",))
        check_rtype(self, partial(policy.get_user_roles,user),
                    set,["user","base"])

    def test_gur_ungrantable(self):
        "test get_user_roles() prevents ungrantable roles"
        policy = policy_01()
        user = stub(roles=("user","base"))
        self.assertRaises(ValueError, policy.get_user_roles, user)
        self.assertRaises(ValueError, policy.get_user_roles, user, inherited=False)

    #=========================================================
    #test user_has_role(user,role,inherited=True)
    #=========================================================
    def test_uhr_simple(self):
        "test user_has_role() basic behavior"
        policy = policy_01()

        user = stub(roles=("user",))
        def func(role):
            return policy.user_has_role(user,role)
        self.assertEqual(func("base"),True)
        self.assertEqual(func("user"),True)
        self.assertEqual(func("pirate"),False)
        self.assertEqual(func("admin"),False)

        user2 = stub(roles=("admin",))
        def func(role):
            return policy.user_has_role(user2,role)
        self.assertEqual(func("base"),True)
        self.assertEqual(func("user"),True)
        self.assertEqual(func("pirate"),True)
        self.assertEqual(func("admin"),True)

    def test_uhr_inherit(self):
        "test user_has_role() inherited=False flag"
        policy = policy_01()

        user = stub(roles=("user",))
        def func(role):
            return policy.user_has_role(user,role,inherited=False)
        self.assertEqual(func("base"),False)
        self.assertEqual(func("user"),True)
        self.assertEqual(func("pirate"),False)
        self.assertEqual(func("admin"),False)

        user2 = stub(roles=("admin",))
        def func(role):
            return policy.user_has_role(user2,role,inherited=False)
        self.assertEqual(func("base"),False)
        self.assertEqual(func("user"),False)
        self.assertEqual(func("pirate"),False)
        self.assertEqual(func("admin"),True)

    #=========================================================
    #test user_has_any_role(user,roles,inherited=True)
    #=========================================================
    def test_uhar_simple(self):
        "test user_has_any_role() basic behavior"
        policy = policy_01()

        user = stub(roles=("user",))
        def func(*roles):
            return policy.user_has_any_role(user,roles)
        self.assertEqual(func("base","pirate"),True)
        self.assertEqual(func("user","pirate"),True)
        self.assertEqual(func("pirate","pirate"),False)
        self.assertEqual(func("admin","pirate"),False)

        user2 = stub(roles=("user","pirate"))
        def func(*roles):
            return policy.user_has_any_role(user2,roles)
        self.assertEqual(func("base"),True)
        self.assertEqual(func("user","pirate"),True)
        self.assertEqual(func("pirate"),True)
        self.assertEqual(func("admin","pirate"),True)

    def test_uhar_inherited(self):
        "test user_has_any_role() inherited=False"
        policy = policy_01()

        user = stub(roles=("user",))
        def func(*roles):
            return policy.user_has_any_role(user,roles, inherited=False)
        self.assertEqual(func("base","pirate"),False)
        self.assertEqual(func("user","pirate"),True)
        self.assertEqual(func("pirate","pirate"),False)
        self.assertEqual(func("admin","pirate"),False)

        user2 = stub(roles=("user","pirate"))
        def func(*roles):
            return policy.user_has_any_role(user2,roles, inherited=False)
        self.assertEqual(func("base"),False)
        self.assertEqual(func("user","pirate"),True)
        self.assertEqual(func("pirate"),True)
        self.assertEqual(func("admin","pirate"),True)

    #=========================================================
    #eoc
    #=========================================================

class RoleHelperTest(TestCase):
    "test policy's role helper functions"
    #=========================================================
    #test expand_roles(roles,rtype=set)
    #=========================================================
    def test_expand_roles(self):
        policy = policy_01()

        #expand from 1
        self.assertElementsEqual(policy.expand_roles(["admin"]),
                                 ["admin", "user", "pirate", "base"])

        #expand from 1 + dup
        self.assertElementsEqual(policy.expand_roles(["admin","user"]),
                                 ["admin", "user", "pirate", "base"])

        #expand from 1 lower
        self.assertElementsEqual(policy.expand_roles(["user"]),
                                 ["user", "base"])

        #expand from 1 lowest
        self.assertElementsEqual(policy.expand_roles(["base"]),
                                 ["base"])

        #expand from none
        self.assertElementsEqual(policy.expand_roles([]),
                                 [])

    def test_expand_roles_rtype(self):
        policy = policy_01()
        elems = ["admin", "pirate", "user", "base"]
        check_rtype(self, partial(policy.expand_roles,["admin", "user"]), set, elems)

    #=========================================================
    #test collapse_roles(roles,rtype=set)
    #=========================================================
    def test_collapse_roles(self):
        #TODO: test rtype option
        policy = policy_01()

        #collapse to top
        self.assertElementsEqual(policy.collapse_roles(["admin", "user", "pirate", "base"]),
                                 ["admin"])

        #collapse to medium
        self.assertElementsEqual(policy.collapse_roles(["user", "pirate", "base"]),
                                 ["pirate","user"])

        #collapse to same
        self.assertElementsEqual(policy.collapse_roles(["user","pirate"]),
                                 ["pirate", "user"])

        #collapse none
        self.assertElementsEqual(policy.collapse_roles([]),
                                 [])

    def test_collapse_roles_rtype(self):
        policy = policy_01()
        elems = ["pirate", "user"]
        check_rtype(self, partial(policy.collapse_roles,["pirate","base", "user"]), set, elems)

    #=========================================================
    #test ascend_roles(roles,rtype=set)
    #=========================================================
    def test_ascend_roles(self):
        policy = policy_01()

        #ascend top
        self.assertElementsEqual(
            policy.ascend_roles(["admin"]),
            [])

        #ascend top and medium
        self.assertElementsEqual(
            policy.ascend_roles(["admin", "pirate"]),
            ["admin"])

        #ascend medium & dup
        self.assertElementsEqual(
            policy.ascend_roles(["user", "pirate","base"]),
            ["admin","user", "pirate"])

        #ascend medium
        self.assertElementsEqual(
            policy.ascend_roles(["user", "pirate"]),
            ["admin"])

        #ascend lowest
        self.assertElementsEqual(
            policy.ascend_roles(["base"]),
            ["admin", "user", "pirate"])

        #ascend none
        self.assertElementsEqual(
            policy.ascend_roles([]),
            [])

    def test_ascend_roles_keep(self):
        policy = policy_01()

        #ascend top
        self.assertElementsEqual(
            policy.ascend_roles(["admin"],keep=True),
            ["admin"])

        #ascend top and medium
        self.assertElementsEqual(
            policy.ascend_roles(["admin", "pirate"],keep=True),
            ["admin","pirate"])

        #ascend medium & dup
        self.assertElementsEqual(
            policy.ascend_roles(["user", "pirate","base"],keep=True),
            ["admin","user", "pirate","base"])

        #ascend medium
        self.assertElementsEqual(
            policy.ascend_roles(["user", "pirate"],keep=True),
            ["admin","user", "pirate"])

        #ascend lowest
        self.assertElementsEqual(
            policy.ascend_roles(["base"],keep=True),
            ["admin", "user", "pirate","base"])

        #ascend none
        self.assertElementsEqual(
            policy.ascend_roles([],keep=True),
            [])

    def test_ascend_roles_rtype(self):
        policy = policy_01()
        elems = [ "admin" ]
        check_rtype(self, partial(policy.ascend_roles, ["pirate"]), set, elems)

    #=========================================================
    #test descend_roles(roles,rtype=set)
    #=========================================================
    def test_descend_roles(self):
        policy = policy_01()

        #descend top
        self.assertElementsEqual(
            policy.descend_roles(["admin"]),
            ["user", "pirate", "base"])

        #descend top and medium
        self.assertElementsEqual(
            policy.descend_roles(["admin", "pirate"]),
            ["user", "pirate", "base"])

        #descend medium & dup
        self.assertElementsEqual(
            policy.descend_roles(["user", "pirate","base"]),
            ["base"])

        #descend medium
        self.assertElementsEqual(
            policy.descend_roles(["user", "pirate"]),
            ["base"])

        #descend lowest
        self.assertElementsEqual(
            policy.descend_roles(["base"]),
            [])

        #descend none
        self.assertElementsEqual(
            policy.descend_roles([]),
            [])

    def test_descend_roles_keep(self):
        policy = policy_01()

        #descend top
        self.assertElementsEqual(
            policy.descend_roles(["admin"], keep=True),
            ["user", "pirate", "base","admin"])

        #descend top and medium
        self.assertElementsEqual(
            policy.descend_roles(["admin", "pirate"], keep=True),
            ["user", "pirate", "base","admin"])

        #descend medium & dup
        self.assertElementsEqual(
            policy.descend_roles(["user", "pirate","base"], keep=True),
            ["base","user","pirate"])

        #descend medium
        self.assertElementsEqual(
            policy.descend_roles(["user", "pirate"], keep=True),
            ["base","user","pirate"])

        #descend lowest
        self.assertElementsEqual(
            policy.descend_roles(["base"], keep=True),
            ["base"])

        #descend none
        self.assertElementsEqual(
            policy.descend_roles([], keep=True),
            [])

    def test_descend_roles_rtype(self):
        policy = policy_01()
        elems = [ "base"]
        check_rtype(self, partial(policy.descend_roles, ["user","pirate"]), set, elems)

    #=========================================================
    #test ensure_valid_roles(roles,grantable=None)
    #=========================================================
    def test_ensure_valid_roles(self):
        "test ensure_valid_roles()"
        policy = policy_01()

        #test no roles
        self.assert_(policy.ensure_valid_roles([]))
        self.assert_(policy.ensure_valid_roles([], grantable=True))
        self.assert_(policy.ensure_valid_roles([], grantable=False))

        #test known roles
        self.assert_(policy.ensure_valid_roles(["user", "base"]))

        #test unknown roles (and combinations w/ known roles)
        self.assertRaises(ValueError, policy.ensure_valid_roles, ["user", "xxx"])
        self.assertRaises(ValueError, policy.ensure_valid_roles, [None])

        #test grantable role
        self.assert_(policy.ensure_valid_roles(["user"], grantable=True))
        self.assertRaises(ValueError, policy.ensure_valid_roles, ["user"], grantable=False)

        #test ungrantable role
        self.assert_(policy.ensure_valid_roles(["base"], grantable=False))
        self.assertRaises(ValueError, policy.ensure_valid_roles, ["base"], grantable=True)

        #check accepts single role string
        #NOTE: this is deprecated, and may be removed in future.
        with catch_all_warnings() as wmsgs:
            self.assert_(policy.ensure_valid_roles("user", grantable=True))
            wmsgs.pop()
            self.assertRaises(ValueError, policy.ensure_valid_roles, "user", grantable=False)
            wmsgs.pop()

    #=========================================================
    #test ensure_valid_role(role,grantable=None)
    #=========================================================
    def test_ensure_valid_role(self):
        "test ensure_valid_role()"
        policy = policy_01()

        #test unknown role
        self.assertRaises(ValueError, policy.ensure_valid_role, None)
        self.assertRaises(ValueError, policy.ensure_valid_role, "xxx")
        self.assertRaises(ValueError, policy.ensure_valid_role, "xxx", grantable=True)
        self.assertRaises(ValueError, policy.ensure_valid_role, "xxx", grantable=False)

        #test grantable role
        self.assert_(policy.ensure_valid_role("user"))
        self.assert_(policy.ensure_valid_role("user", grantable=True))
        self.assertRaises(ValueError, policy.ensure_valid_role, "user", grantable=False)

        #test ungrantable role
        self.assert_(policy.ensure_valid_role("base"))
        self.assertRaises(ValueError, policy.ensure_valid_role, "base", grantable=True)
        self.assert_(policy.ensure_valid_role("base", grantable=False))

    #=========================================================
    #eoc
    #=========================================================

class PermissionCreationTest(TestCase):
    "test policy's permission & link creation functions"
    #=========================================================
    #test permit(roles, action, *a, **k) -> perm_obj
    #=========================================================
    def test_permit(self):
        "test permit()"
        policy = policy_01()
        self.assertEquals(policy._links,[])

        a = policy.permit(["admin"], "perm-a")
        b = policy.permit(["user","pirate"],"perm-b")
        l1,l2 = policy._links

        self.assertEqual(l1.perm_objs, [a])
        self.assert_sets_equal(l1.base_roles,["admin"])
        ##self.assert_sets_equal(l1.expanded_roles,["admin"])

        self.assertEqual(l2.perm_objs, [b])
        self.assert_sets_equal(l2.base_roles,["user",'pirate'])
        ##self.assert_sets_equal(l2.expanded_roles,["admin","user","pirate"])

    def test_permit_string(self):
        "test permit() w/ single role as string"
        policy = policy_01()
        self.assertEquals(policy._links,[])
        a = policy.permit("admin","perm-a")
        l1, = policy._links
        self.assertEqual(l1.perm_objs, [a])
        self.assert_sets_equal(l1.base_roles,["admin"])

    #=========================================================
    #test permit_list(roles, perm_descs) -> perm_objs
    #=========================================================
    def test_permit_list(self):
        "test permit_list()"
        policy = policy_01()
        self.assertEquals(policy._links,[])
        a, = policy.permit_list(["admin"],[dict(action="perm-a")])
        b,c = policy.permit_list(["user","pirate"],[dict(action="perm-a"),
                                            dict(action="perm-b")])
        l1,l2 = policy._links
        self.assertEqual(l1.perm_objs, [a])
        self.assert_sets_equal(l1.base_roles,["admin"])
        ##self.assert_sets_equal(l1.expanded_roles,["admin"])

        self.assertEqual(l2.perm_objs, [b,c])
        self.assert_sets_equal(l2.base_roles,["user",'pirate'])
        ##self.assert_sets_equal(l2.expanded_roles,["admin","user","pirate"])

    def test_permit_list_string(self):
        "test permit_list() w/ single role as string"
        policy = policy_01()
        self.assertEquals(policy._links,[])
        a, = policy.permit_list("admin",[dict(action="perm-a")])
        l1, = policy._links
        self.assertEqual(l1.perm_objs, [a])
        self.assert_sets_equal(l1.base_roles,["admin"])

    #=========================================================
    #test create_permission(action, *a, **k) -> perm
    #=========================================================
    def test_create_permission(self):
        "test create_permission"
        policy = Policy()
        p = policy.create_permission("update")
        self.assertEqual(p.action, "update")
        self.assertIs(p.klass, None)
        self.assertIs(p.attrs,None)

        p2 = policy.create_permission("update", "test")
        self.assertEqual(p2.action, "update")
        self.assertIs(p2.klass, "test")
        self.assertIs(p.attrs,None)

        p3 = policy.create_permission("update", "test", attrs=("bob",))
        self.assertEqual(p3.action, "update")
        self.assertIs(p3.klass, "test")
        self.assert_sets_equal(p3.attrs, ["bob"])

        policy.freeze()
        self.assertRaises(AssertionError, policy.create_permission, "edit")

    def test_create_permission_subclassed(self):
        "test create_permission() honors Policy.Permission"
        #make sure orig Perm won't take "xxx"
        self.assertRaises(TypeError, Policy.Permission, "test", xxx=23)

        #create role subclass which accepts "xxx"
        class MyPermission(Policy.Permission):
            def __init__(self, *a, **k):
                self.xxx = k.pop("xxx",None)
                self.__super.__init__(*a,**k)

        #create policy class which uses MyRole
        class MyPolicy(Policy):
            Permission = MyPermission

        #try creating role, make sure MyRole was used
        policy = MyPolicy()
        r = policy.create_permission("test", xxx=23)
        self.assertIsInstance(r,MyPermission)
        self.assertEqual(r.xxx, 23)

    #=========================================================
    #test create_link(perm_objs, roles)
    #=========================================================
    def test_create_link(self):
        "test create_link()"
        policy = policy_01()
        a = policy.create_permission("perm-a")
        b = policy.create_permission("perm-b")
        c = policy.create_permission("perm-c")
        self.assertEquals(policy._links,[])

        policy.create_link([a],['admin'])
        policy.create_link([b,c],['user','pirate'])
        l1,l2 = policy._links

        self.assertEqual(l1.perm_objs, [a])
        self.assert_sets_equal(l1.base_roles,["admin"])
        ##self.assert_sets_equal(l1.expanded_roles,["admin"])

        self.assertEqual(l2.perm_objs, [b,c])
        self.assert_sets_equal(l2.base_roles,["user",'pirate'])
        ##self.assert_sets_equal(l2.expanded_roles,["user","pirate","admin"])

    def test_create_link_string(self):
        "test create_link() with single role as string"
        policy = policy_01()
        a = policy.create_permission("perm-a")
        b = policy.create_permission("perm-b")
        c = policy.create_permission("perm-c")
        self.assertEquals(policy._links,[])

        policy.create_link([a],'admin')
        l1, = policy._links

        self.assertEqual(l1.perm_objs, [a])
        self.assert_sets_equal(l1.base_roles,["admin"])
        ##self.assert_sets_equal(l1.expanded_roles,["admin"])

    #=========================================================
    #eoc
    #=========================================================

class PermissionExaminationTest(TestCase):
    "test policy's permission & link examination functions"
    #=========================================================
    #user_has_permission
    #=========================================================
    #test positional params (action, klass, item)
    #test kwd params (attr, scope)

    def test_uhp(self):
        "test basic user_has_permission() functions"
        policy, admin, employee, client, User = policy_03x()

        #check everyone inherits from 'person'
        self.assert_(admin.has_permission("sign-in"))
        self.assert_(employee.has_permission("sign-in"))
        self.assert_(client.has_permission("sign-in"))

        #double-check guards are working
        self.assert_(employee.has_permission("update","user",employee))
        self.assert_(not employee.has_permission("update","user",admin))

        #check guard works for generic case
        self.assert_(employee.has_permission("retire", "user"))
        self.assert_(employee.has_permission("retire", "user", client))
        self.assert_(not employee.has_permission("retire", "user", employee))

        #check klass=False works
        self.assert_(not admin.has_permission("sign-in", "user"))

        #check klass=True works
        self.assert_(not admin.has_permission("delete"))
        self.assert_(admin.has_permission("delete", "user"))

        #check inheritance matches down, not up
        self.assert_(not employee.has_permission("delete", "user"))

        #check attrs & deny are working properly
        self.assert_(client.has_permission("update","journal"))
        self.assert_(client.has_permission("update","journal", attr="date"))
        self.assert_(not client.has_permission("update","journal", attr="owner"))

    def test_uhp_params(self):
        "test user_has_permission() positional vs kwd arguments"

        policy, admin, employee, client, User = policy_03x()

        #all kwds
        self.assert_(employee.has_permission(action="update", klass="user", attr="xxx", item=employee))

        #min positionals
        self.assert_(employee.has_permission("sign-in"))
        self.assert_(employee.has_permission("sign-in",attr="xxx"))

        #too few positionals
        self.assertRaises(TypeError, employee.has_permission, attr="xxx")

        #all possible positionals
        self.assert_(employee.has_permission("update", "user", employee, attr="xxx"))

        #too many positionals
        self.assertRaises(TypeError, employee.has_permission,
                          "update", "user", employee, "xxx")

        #unknown kwds
        self.assertRaises(TypeError, employee.has_permission,
                          "update", "user", employee, xxx="xxx")

    #=========================================================
    #test get_user_permissions(user,rtype=tuple)
    #=========================================================
    #NOTE: get_user_permissions() wraps get_role_permissons,
    # so we rely on that test for more complicated inputs.
    def test_gup_simple(self):
        "test get_user_permissions()"
        policy,a,b,u,p = policy_02x()

        user = stub(roles=())
        self.assertEquals(policy.get_user_permissions(user,rtype=list),[])

        user = stub(roles=("user",))
        self.assertEquals(policy.get_user_permissions(user,rtype=list),[b,u])

        user = stub(roles=("admin",))
        self.assertEquals(policy.get_user_permissions(user,rtype=list),[a,b,u,p])

    def test_gup_rtype(self):
        policy,a,b,u,p = policy_02x()

        user = stub(roles=("user", "pirate"))
        elems = [b,u,p]
        check_rtype(self, partial(policy.get_user_permissions,user), tuple, elems, ordered=True)

    #=========================================================
    #test get_role_permissions(roles, inherited=True, rtype=tuple)
    #=========================================================
    def test_grp_00(self):
        "test get_role_permissions() works under frozen & thawed modes"
        policy = policy_01()
        self.assertElementsEqual(policy.get_role_permissions(["user"]),[])
        policy.freeze()
        self.assertElementsEqual(policy.get_role_permissions(["user"]),[])
    #NOTE: current implementation no longer forces policy to be frozen
    ##    "test get_role_permissions() requires frozen policy object"
    ##    policy = policy_01()
    ##    self.assertRaises(AssertionError, policy.get_role_permissions, ["client"])
    ##    policy.freeze()
    ##    self.assertElementsEqual(policy.get_role_permissions(["client"]),[])

    def test_grp_01(self):
        "test get_role_permissions() obeys role inheritance chain"
        #test perms reported for correct roles
        policy,a,b,u,p = policy_02x()

        #test non-inherited permissions are listed correctly
        def grp(*roles):
            return list(policy.get_role_permissions(roles, inherited=False))
        self.assertEqual(grp("base"),[b])
        self.assertEqual(grp("user"),[u])
        self.assertEqual(grp("admin"),[a])
        self.assertEqual(grp("pirate"),[p])

        #test inherited permissions are listed correctly and in order
        def grp(*roles):
            return list(policy.get_role_permissions(roles))
        self.assertEqual(grp("base"),[b])
        self.assertEqual(grp("user"),[b,u])
        self.assertEqual(grp("admin"),[a,b,u,p])
        self.assertEqual(grp("pirate"),[b,p])

    def test_grp_02(self):
        "test get_role_permissions() handles multiple roles"
        #test perms reported for correct roles
        policy,a,b,u,p = policy_02x()

        #test non-inherited permissions are listed correctly
        def grp(*roles):
            return list(policy.get_role_permissions(roles, inherited=False))
        self.assertEqual(grp("base","user"),[b,u])
        self.assertEqual(grp("pirate","user"),[u,p])
        self.assertEqual(grp("admin","base"),[a,b])
        self.assertEqual(grp("admin","pirate"),[a,p])

        #test inherited permissions are listed correctly and in order
        def grp(*roles):
            return list(policy.get_role_permissions(roles))
        self.assertEqual(grp("base","user"),[b,u])
        self.assertEqual(grp("pirate","user"),[b,u,p])
        self.assertEqual(grp("admin","base"),[a,b,u,p])
        self.assertEqual(grp("admin","pirate"),[a,b,u,p])

    def test_grp_priority(self):
        "test get_role_permissions() obeys priority"
        policy = policy_01()
        b = policy.permit("base", "perm-b")
        p = policy.permit("pirate", "perm-p", priority=-10)
        u = policy.permit("user", "perm-u", priority=10)
        a = policy.permit("admin", "perm-a")
        #NOTE: w/o priority, order would be b,p,u,a
        policy.freeze()

        def grp(*roles):
            return list(policy.get_role_permissions(roles))
        self.assertEqual(grp("base"),[b])
        self.assertEqual(grp("user"),[u,b])
        self.assertEqual(grp("admin"),[u,b,a,p])
        self.assertEqual(grp("pirate"),[b,p])

    def test_grp_rtype(self):
        "test get_role_permissions() rtype option"
        policy,a,b,u,p = policy_02x()
        elems = [a,b,u,p]
        check_rtype(self,partial(policy.get_role_permissions,["admin"]), tuple, elems)

    def test_grp_string(self):
        "test get_role_permissions() w/ single role as string"
        policy,a,b,u,p = policy_02x()
        self.assertElementsEqual(policy.get_role_permissions("user"),[b,u])

    #=========================================================
    #get_linked_roles(perm_obj, inherited=True, limit_roles=None, rtype=set)
    #=========================================================
    def test_glr_basic(self):
        "test get_linked_roles() basic behavior"
        policy,a,b,u,p = policy_02x()

        results = policy.get_linked_roles(a)
        self.assert_sets_equal(results,["admin"])

        results = policy.get_linked_roles(b)
        self.assert_sets_equal(results,["admin","base","user", "pirate"])

        results = policy.get_linked_roles(u)
        self.assert_sets_equal(results,["admin","user"])

        results = policy.get_linked_roles(p)
        self.assert_sets_equal(results,["admin","pirate"])

    def test_glr_inherited(self):
        "test get_linked_roles() inherited=False flag"
        policy,a,b,u,p = policy_02x()

        results = policy.get_linked_roles(a, inherited=False)
        self.assert_sets_equal(results,["admin"])

        results = policy.get_linked_roles(b, inherited=False)
        self.assert_sets_equal(results,["base"])

        results = policy.get_linked_roles(u, inherited=False)
        self.assert_sets_equal(results,["user"])

        results = policy.get_linked_roles(p, inherited=False)
        self.assert_sets_equal(results,["pirate"])

    def test_glr_limit_roles(self):
        "test get_linked_roles() limit_roles kwd"
        policy,a,b,u,p = policy_02x()

        #check no roles
        results = policy.get_linked_roles(a, limit_roles=[])
        self.assert_sets_equal(results,[])

        #check restricting roles
        results = policy.get_linked_roles(b, limit_roles=["user", "pirate"])
        self.assert_sets_equal(results,["user", "pirate"])

        #check unused + used roles
        results = policy.get_linked_roles(u, limit_roles=["admin", "user", "base"])
        self.assert_sets_equal(results,["admin","user"])

        #check unused roles
        results = policy.get_linked_roles(p, limit_roles=["user"])
        self.assert_sets_equal(results,[])

    def test_glr_rtype(self):
        "test get_linked_roles() rtype kwd"
        policy,a,b,u,p = policy_02x()

        match = ["admin", "base", "user", "pirate"]
        check_rtype(self, partial(policy.get_linked_roles,b), set, match)

    #=========================================================
    #test could_allow()
    #=========================================================
    def test_ca_basic(self):
        "test policy.could_allow()"
        policy, admin, employee, client, User = policy_03x()

        #test one with a guard in the perms
        self.assert_(policy.could_allow("update", "user"))
        
        #test one that's not listed
        self.assert_(not policy.could_allow("smile-at", "user"))
        
        #test one with a deny rule in the perms
        self.assert_(policy.could_allow("update", "journal", attr="owner"))

    #=========================================================
    #eoc
    #=========================================================

class MiscTest(TestCase):
    "test misc policy functions"
    #=========================================================
    #inspect_user_roles
    #=========================================================
    def test_iur_default(self):
        policy = policy_01()
        u = stub(roles=("user",))
        self.assertElementsEqual(policy.get_user_roles(u,inherited=False),["user"])
        self.assertElementsEqual(policy.get_user_roles(u),["user", "base"])

    def test_iur_override(self):
        policy = policy_01(inspect_user_roles=lambda u: u.alt_roles)
        u = stub(alt_roles=("user",))
        self.assertElementsEqual(policy.get_user_roles(u,inherited=False),["user"])
        self.assertElementsEqual(policy.get_user_roles(u),["user", "base"])

    def test_iur_valid(self):
        policy = policy_01()
        u = stub(roles=("user","xxx"))
        self.assertRaises(ValueError, policy.get_user_roles, u)
        #KeyError: xxx role undefined

    def test_iur_grantable(self):
        policy = policy_01()
        u = stub(roles=("user","base"))
        self.assertRaises(ValueError, policy.get_user_roles, u)
        #ValueError: base role not grantable

    #=========================================================
    #freeze() and frozen
    #=========================================================
    def test_freeze(self):
        "test freeze() and .frozen"
        policy = Policy()
        self.assert_(not policy.frozen)
        policy.freeze()
        self.assert_(policy.frozen)
        self.assertRaises(AssertionError, policy.freeze)

    #=========================================================
    #ensure_frozen
    #=========================================================
    def test_ensure_frozen(self):
        policy = Policy()
        self.assertRaises(AssertionError, policy.ensure_frozen)
        policy.freeze()
        self.assert_(policy.ensure_frozen())

    #=========================================================
    #ensure_thawed
    #=========================================================
    def test_ensure_thawed(self):
        policy = Policy()
        self.assert_(policy.ensure_thawed())
        policy.freeze()
        self.assertRaises(AssertionError, policy.ensure_thawed)

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#eof
#=========================================================
