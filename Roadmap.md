# Overview #

This document provides a tentative roadmap for Passlib's future development.
While the core featureset and interface are quite stable,
various bits (especially the internals) are still being improved.

In order to minimize the disruption to users, this is being done very slowly:
deprecated bits should be kept around for at least one major release, and the goal is to slow things down to around 1 year between major releases.

Going forward, the following milestones have been planned:

# Passlib 1.7 #

  * Dropping Python 2.5 & Django <= 1.3.x support, unless receive a ton of requests not to.

  * [scrypt hash support](https://code.google.com/p/passlib/issues/detail?id=8). Work halfway done in scrypt-dev branch.

  * Add [pepper support](https://code.google.com/p/passlib/issues/detail?id=38). Needs CryptContext and PasswordHash apis, and custom hashes. Work should be happening in the pepper-dev branch.

  * [Password entropy estimator](https://code.google.com/p/passlib/issues/detail?id=48). Current default branch contains a rough entropy estimator in `passlib.pwd`. Need to finish it up, add tests, and document all the better estimators out there which people should use if they're serious :)

  * Password generation helpers. Current default branch contains `passlib.pwd` module, with an enhanced version of the `passlib.utils.generate_password()` helper. Need to finalize api and unittests. Should mostly be ready for release.

  * _Possibly_: Extension providing [TOTP](https://code.google.com/p/passlib/issues/detail?id=44) support. A start has been made in the default branch, but time constraints may prevent this from being ready for 1.7. Should either finish it up, or move to separate branch and delay until later release.

  * _Possibly_: rename registry methods to match CryptContext... e.g. `registry.list_crypt_handlers()` -> `registry.schemes()`. Would be more predictable an api.

# Passlib 1.8 #

  * Remove `C`ryptPolicy framework and some other features that were deprecated in Passlib 1.6.

  * Command line tool support ([issue 33](https://code.google.com/p/passlib/issues/detail?id=33)). Should do this before that branch suffers bitrot.

# Before Passlib 2.0 #

  * Deal with hash parsing api ([issue 37](https://code.google.com/p/passlib/issues/detail?id=37)).

  * Relocate crypto primitives to `passlib.utils.crypto`, instead of scattered across multiple submodules. Benefits: smaller namespace for users, and internally the code can dynamically import only the needed components. Deprecate existing crypto modules (des, pbkdf2, md4, `_`blowfish) until Passlib 2.0.

# Passlib 2.0 #

  * Clean out all deprecated modules and APIs still remaining in passlib.

  * Resolve a few remaining issues that will probably require api changes -- salt & digest encoding, api naming ([issue 38](https://code.google.com/p/passlib/issues/detail?id=38))