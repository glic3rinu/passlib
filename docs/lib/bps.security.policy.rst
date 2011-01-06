==================================================================
:mod:`bps.security.policy` -- Lightweight Access Control Framework
==================================================================

.. module:: bps.security.policy
    :synopsis: lightweight access control framework

Overview
========
This module provides a framework for applications
to build complex permission and security policies,
centered around the common "user -> role -> permission" pattern.
This framework is derived from one deployed in a few web applications,
which in turn was inspired by Roundup's `access control mechanism <http://www.roundup-tracker.org/docs/design.html#access-control>`_.
Never-the-less, it's generic enough that it should be suitable for use
by gui and command line applications as well.

An application can make use of this framework by:

    * creating a :class:`Policy` instance for the application.
    * registering all potential roles with the policy
    * registering all permissions, as expressed
      in terms of actions, roles, and optional guard functions.
    * querying the policy either to enumerate a given user's permissions,
      or check if the user has permission to perform a specific action.

.. _permission-question:

Framing a Permission Question
=============================

.. todo:: finish write up the structure of the "permission question"

When an application needs to test whether a user has permission
to perform a given action, the first thing that must be done
to use any policy framework is to encode the question in a format
the permission system understands. This module encodes
permission questions using the following 5 parameters:

    * ``action`` - a string, usually a verb such as ``"update"``,
       which represents the action permission is being requested for.

    * ``klass`` - optional string, usually a noun such as ``"BlogEntry"``
       which the action will be acting upon. (Some actions
       act globally, and won't have a class specified).

    * ``item`` - optional object, usually an instance of the class identified by ``klass``.
       This is generally used when the permission applies to only certain instances
       of the class, which must be decided on a case-by-case basis.

    * ``attr`` - optional string, usually a attribute of ``klass`` such as ``"date"``.
       This is typically used when the action is restricted on a per-attribute basis.

    * ``scope`` - optional object, usually the owner of the instance
      being acted on, or a composite object which the action is being
      performed inside of. This is needed very rarely, but there are
      some cases, such as when requesting permission to create
      a new instance of class which will be stored inside a particular
      object, and that object affects the outcome of the permission check.

Combinations of 1 or more of these parameters can be put together
in order to encode the following questions:

    1. ``Does {user} have permission to {action}?``

    2. ``Does {user} have permission to {action} an object of type {klass}?``.

    3. ``Does {user} have permission to {action} the object {item} of type {klass}?``

    4. ``Does {user} have permission to {action} the attribute {attr} of an object of type {klass}?``

    5. ``Does {user} have permission to {action} the attribute {attr} of the object {item} of type {klass}?``

    6. ``Does {user} have permission to {action} an object of type {klass} as part of {scope}?``.
        As an exmaple: does the user have permission to *create* an object of type
        *entry* as part of *<a specific journal instance>*?

Usage Example
=============

.. todo:: write usage example for sec policy

The Policy Class
================

.. autoclass:: Policy

The Support Classes
===================
The following classes are used internally by :class:`Policy`,
and generally the programmer will not need to create them directly
(though they may need to examine them if preparing a list of
the user's permissions for display).

.. autoclass:: Role

.. autoclass:: Permission

..
    Not documenting these right now, the system is usuable without
    knowledge of this bit, although they could be usuable by the guard func,
    but no use-case has needed this just yet:

    .. _permissions-constants:

    .. autoclass:: PERM
