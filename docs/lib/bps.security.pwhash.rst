=============================================
:mod:`bps.security.pwhash` - Password Hashing
=============================================

.. module:: bps.security.pwhash
    :synopsis: password hashing (unix-crypt, md5-crypt, etc)

Overview
========
This module handles encrypting and verifying password hashes
(such as from unix shadow files). This module contains implementations of most
of the modern password hashing algorithms,
as well as a complex framework for implementing
new algorithms, managing hashes generated
within different contexts with different supported
algorithms, and other features.

The algorithms currently supported by default in BPS:

    * Unix-Crypt
    * MD5-Crypt
    * BCrypt
    * SHA-Crypt (256 & 512 bit modes)
    
    * PostgreSQL & MySQL password hashes

Sections
========
The documentation for the pwhash module is broken into the following sections:

* :doc:`Quick Start <bps.security.pwhash/quickstart>` -- frontend funcs for quickly creating / validating hashes
* :doc:`Crypt Contexts <bps.security.pwhash/contexts>` -- for using just the algorithms your application needs
* :doc:`Crypt Algorithms <bps.security.pwhash/algorithms>` -- details of the algorithms BPS implements
* :doc:`Implementing a Custom Crypt Algorithm <bps.security.pwhash/implementation>` -- Roll your own
* :doc:`Helper Functions <bps.security.pwhash/utils>`

.. toctree::
    :hidden:

    bps.security.pwhash/quickstart
    bps.security.pwhash/contexts
    bps.security.pwhash/algorithms
    bps.security.pwhash/implementation
    bps.security.pwhash/utils
