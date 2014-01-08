=======
Project
=======

shade is a security access library.

Introduction
============

shade provides access to security libraries that support event driven TLS. It's purpose is
to provide an abstraction to various mature implementations so that secure transport may
be implemented independent of the underlying means.

Structure
=========

Currently, shade only provides access to OpenSSL, a C-API module: :py:mod:`shade.openssl`.

Requirements
============

Recent version of OpenSSL. Version 1.0 or greater is likely required.
Requires fault.io/python/xeno in order to compile the C-API module.

Conventions
===========

None of significance.

Defense
=======

There are no OpenSSL bindings that purely target asynchronous operations. Specifically,
shade is interested in BSD-socket independent TLS for security over arbitrary Python-level
transports.
