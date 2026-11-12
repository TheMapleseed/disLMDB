Tribute to Howard Chu
=====================

DisLMDB is built on Lightning Memory-Mapped Database (LMDB), which Howard Chu
created. He does not have his own Wikipedia biography; the English article that
covers his work is
`Lightning Memory-Mapped Database <https://en.wikipedia.org/wiki/Lightning_Memory-Mapped_Database>`_,
where he is listed as the original author. This note is a short tribute, and a
plain-English record of what that page says.

Howard Chu is CTO and co-founder of Symas Corporation, and chief architect of
the OpenLDAP Project. He is also known for SQLightning (SQLite running on
LMDB), OpenLDAP’s back-mdb, and—outside of software—for playing Irish fiddle.
More about LMDB is at `symas.com/lmdb <https://symas.com/lmdb>`_; his site is
`highlandsun.com <https://highlandsun.com>`_.

He designed LMDB so OpenLDAP could stop fighting Berkeley DB’s stacked caches
and lean on one memory-mapped store managed by the OS. The result is a small,
crash-resistant B+ tree engine with copy-on-write pages and read scaling that
grows with cores. DisLMDB keeps that core—ACID transactions, zero-copy maps,
B+ trees—and adds distribution on top. Credit for LMDB itself stays with Howard
Chu and the Symas / OpenLDAP community.

What the English Wikipedia article covers
-----------------------------------------

The article’s infobox names the project OpenLDAP Lightning Memory-Mapped
Database, credits Howard Chu as original author and Symas as developer, gives a
first release of 24 November 2011, and describes it as a C embedded key-value
store under the OpenLDAP Public License, roughly tens of kilobytes of object
code, running on Unix-family systems, Windows, and related platforms. The site
and git tree live under the OpenLDAP / Symas umbrella.

Lead
~~~~

LMDB is an embedded transactional key-value store, not a relational database.
Keys and values are opaque byte arrays. It supports range search, multiple
values per key, and an append mode (``MDB_APPEND``) when keys are already
sorted. Many threads or processes can share a store; readers scale linearly; a
single writer does not block readers, and readers do not block the writer.
Several applications on one machine can open the same map. There is no separate
transaction log—integrity comes from the copy-on-write design, which also
avoids writing every change twice.

History
~~~~~~~

The design was hashed out on the OpenLDAP developer list in 2009 as a way out
of Berkeley DB’s cache complexity. Work started from related OpenBSD ldapd
code. Public sources showed up in the OpenLDAP tree in June 2011 under the name
MDB; in November 2012 it was renamed LMDB to avoid colliding with other
software.

How it works
~~~~~~~~~~~~

Internally it is B+ trees in a shared memory map with copy-on-write. Tree nodes
line up with OS pages. Updates do not overwrite live pages, so the file stays
consistent without a redo log. ``MDB_APPEND`` can bulk-load sorted keys
cheaply. Callers can get pointers straight into the map instead of copying
large values. Freed pages are tracked in their own tree and reused, so there is
no garbage-collection pause. The on-disk format depends on architecture (word
size and endianness), so moving files between machines is not always a
straight copy.

Concurrency uses multiversion concurrency control. Writers take a mutex;
readers mostly run wait-free and in parallel with the writer. Writers look at a
shared reader table to see which versions they still have to keep.

Performance and reliability
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Symas plugged LMDB into Google’s LevelDB-style micro-benchmarks alongside
Berkeley DB. Those numbers, and later in-memory and on-disk studies, generally
put LMDB at the front for reads and many batch writes; the filesystem
underneath still matters a lot. OpenLDAP shops that switched from back-hdb to
back-mdb (Zimbra among them) reported large gains.

Because pages are never overwritten in place, a crash usually cannot leave a
corrupt tree—you may only lose the last uncommitted write. USENIX OSDI crash
papers discuss edge cases around fsync versus fdatasync on Linux; that choice
is a compile-time option in LMDB.

License
~~~~~~~

When Oracle moved Berkeley DB to AGPL in 2013, distributors looked for
alternatives. Howard Chu made clear that LMDB sits in OpenLDAP’s long BSD-style
license tradition, and that check-ins do not assign copyright in a way that
would let someone pull an Oracle-style license change. Debian and others moved
toward LMDB for that reason as much as for performance.

Ports and use
~~~~~~~~~~~~~

Wrappers exist for a long list of languages (C++, Java, Python, Lua, Rust, Go,
Ruby, and many others). Chu also shipped SQLightning—SQLite 3.7.7.1 with LMDB
under it—and reported large insert speedups on simple tests. Projects that have
used LMDB include Cyrus SASL, Heimdal, OpenDKIM, Postfix’s lmdb_table,
PowerDNS, CFEngine, Knot DNS, Monero, Nano, Meilisearch, Samba’s AD stack, and
others catalogued on the Symas site. Redis was experimented with as a
persistence backend as well.

Reviewers tend to say the brilliance is in combining old ideas (B+ trees,
copy-on-write, MVCC) into something tiny and reliable. Oren Eini’s long walk
through the code called the design impressive while complaining about style and
duplication. Wikipedia also mentions libmdbx (MDBX), a deeper fork used in some
blockchain and security products.

Closing
-------

This file lives in the repo root so contributors see where the storage engine
came from. DisLMDB’s distributed layer is separate work; LMDB remains under the
OpenLDAP Public License, and we do not claim to have invented it. If you ship
or cite DisLMDB, please mention LMDB and Howard Chu as well.

Source:
`en.wikipedia.org/wiki/Lightning_Memory-Mapped_Database <https://en.wikipedia.org/wiki/Lightning_Memory-Mapped_Database>`_.
Wikipedia content is under CC BY-SA; this is an attribution note for the
project, not a replacement for the live article.
