=============
Build FINCHFS
=============

Requirements
============

* `UCX <https://openucx.readthedocs.io/en/master/>`_ v1.14.1
* `pmemkv <https://pmem.io/pmemkv/>`_ (For pmemkv backend)

Quick installation steps
========================

.. code-block:: bash

    $ git clone -c feature.manyFiles=true --depth 1 https://github.com/spack/spack.git
    $ . spack/share/spack/setup-env.sh
    $ git clone https://github.com/tsukuba-hpcs/spack-packages
    $ spack repo add ./spack-packages
    $ spack install finchfs

Build from source
=================

.. code-block:: bash

    $ autoreconf -i
    $ ./configure [--prefix=PREFIX] [--with-pmemkv]
    $ make
    $ make install
