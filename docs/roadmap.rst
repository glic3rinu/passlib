=======
Roadmap
=======

Planned Features
================
The follow is the list of pending tasks which definitely need to be completed
for BPS, roughly in the order they will probably get done:

* Finish rewriting and documentation BPS's enhancements to the
  standard logging system.

* Clean up "bps.host" interface system, and document it.

* Make sure config_parser module has been converted.

* Unittests do not have good overall coverage.

* The following modules have yet to be documented:

    - bps.numeric
    - bps.undef
    - bps.logs

* Release to public.
  This is being put off until documentation and unittests are fleshed out more,
  and some needed redesigns are done before external apps become dependant
  on legacy behaviors.

Wishlist
========
The following are things which it would be nice to add to BPS,
but the need is not pressing, and no particular plans have been drawn up:

* Merge into BPS the security policy framework
  currently used by many of our projects.
  (probably under "bps.security.policy").

* Fix major bug: :func:`bps.fs.filepath` does not support unicode.

* Merge in the planetbox numeric and stream routines.

* Merge in the threading and dispatcher routines
  from internal "pxhelpers" library.

* Merge into BPS the user-interaction subsystem from our internal
  "automigrate" library (probably under "bps.host.interact").

* Merge in "signals", "app.locking", and "app.command"
  packages from the internal company library "astllc".

Todos
=====
.. todolist::
