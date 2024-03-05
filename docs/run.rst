===========
Run FINCHFS
===========

Run finchfsd
============

``finchfsd`` starts with MPI. The finchfsd options are the following.

* ``-c db_dir`` : specifies a database directory or a DAX device. If the directory does not exist, it will be created.
* ``-s db_size`` : specifies a database size. This option is only effective when using the pmemkv and fsdax. Default is 1 GiB.
* ``-v log_level`` : specifies the log level (e.g. debug). Default is info.

An example of a script is the following.

.. code-block:: bash

    NUM_NODES=10
    NUM_CLIENTS=$((NUM_NODES * 24)) # ppn is 24
    FINCHFSD_PPN=8
    FINCH_DB_SIZE=$((1024 * 1024 * 1024 * 1024)) # 1 TiB
    export UCX_NUM_EPS=$NUM_CLIENTS
    mpirun -np $((NUM_NODES*FINCHFSD_PPN)) -hostfile /path/to/hostfile --map-by ppr:$FINCHFSD_PPN:node:PE=1 -x UCX_NUM_EPS finchfsd -c /scr -s $FINCH_DB_SIZE -v debug &
    sleep 5 # wait for finchfsd to start

When we use pmemkv backend with devdax mode, 
we need to create namespaces for the number of threads, by `ndctl <https://docs.pmem.io/ndctl-user-guide/ndctl-man-pages/ndctl-create-namespace>`_.
We specify the ``-c /dev/dax0.%d`` option to ``finchfsd``, then ``finchfsd`` use ``/dev/dax0.0``, ``/dev/dax0.1``, ..., ``/dev/dax0.$((NUM_THREADS - 1))``.

.. code-block:: bash

    mpirun -np $((NUM_NODES*FINCHFSD_PPN)) --map-by ppr:$FINCHFSD_PPN:node:PE=1 -x UCX_NUM_EPS finchfsd -c /dev/dax0.%d -s $FINCH_DB_SIZE -v debug &

``/tmp/finchfsd`` is the `address file` and generated on the compute node where finchfsd is started.
FINCHFS client library connect to finchfsd by the address file.

Use FINCHFS client library
==========================

FINCHFS client library can be used by pkg-config.

.. code-block:: bash

    $ export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/path/to/finchfs/lib/pkgconfig
    $ pkg-config --cflags finchfs
    -I/path/to/finchfs/include -I/path/to/ucx/include
    $ pkg-config --libs finchfs
    -L/path/to/finchfs/lib -L/path/to/ucx/lib -lfinchfs -lucp -luct -lucs -lucm

First, write application code ``hello.c``.

.. code-block:: c

    #include <stdlib.h>
    #include <fcntl.h>
    #include <finchfs.h>

    int
    main(int argc, char **argv)
    {
        if (finchfs_init(NULL)) {
            return (-1);
        }
        int fd;
        if ((fd = finchfs_create("/hello", 0, S_IRWXU)) < 0) {
            return (-1);
        }
        if (finchfs_close(fd)) {
            return (-1);
        }
        finchfs_term();
        return (0);
    }

Second, compile the application code.

.. code-block:: bash

    $ gcc `pkg-config --cflags finchfs` hello.c `pkg-config --libs-only-L finchfs | sed 's/-L/-Wl,-rpath,/g'` `pkg-config --libs finchfs`

Finally, run the application code.

.. code-block:: bash

    $ ./a.out

We can set environment variables for FINCHFS client library.

* ``FINCHFS_LOG_LEVEL`` : specifies the log level (e.g. debug). Default is info.
* ``FINCHFS_CHUNK_SIZE`` : specifies the chunk size. Default is 64 KiB.
