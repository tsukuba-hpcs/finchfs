=============
Build FINCHFS
=============

Requirements
============

* `UCX <https://openucx.readthedocs.io/en/master/>`_ v1.14.1
* `pmemkv <https://pmem.io/pmemkv/>`_ (For pmemkv backend)

Build from source
=================

.. code-block:: bash

    $ autoreconf -i
    $ ./configure [--prefix=PREFIX] [--with-pmemkv]
    $ make
    $ make install
