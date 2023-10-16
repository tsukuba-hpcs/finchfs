===========
Run FINCHFS
===========

Run finchfsd
============

``finchfsd`` starts with MPI. The finchfsd options are the following.

* ``-c db_dir`` : specifies a database directory or a DAX device. If the directory does not exist, it will be created.
* ``-s db_size`` : specifies a database size. This option is only effective when using the pmemkv and fsdax. Default is 1 GiB.
* ``-t num_threads`` : specifies the number of threads of the finchfsd. Default is 1.
* ``-v log_level`` : specifies the log level (e.g. debug). Default is info.

An example of a script is the following.

.. code-block:: bash

    NUM_NODES=10
    NUM_CLIENTS=$((NUM_NODES * 24)) # ppn is 24
    NUM_THREADS=8
    FINCH_DB_SIZE=$((1024 * 1024 * 1024 * 1024)) # 1 TiB
    export UCX_IB_MLX5_DEVX=n
    export UCX_IB_REG_METHODS=odp,direct
    export UCX_NUM_EPS=$NUM_CLIENTS
    mpirun -np $NUM_NODES -hostfile /path/to/hostfile --map-by ppr:1:node:PE=$NUM_THREADS -x UCX_IB_MLX5_DEVX -x UCX_IB_REG_METHODS -x UCX_NUM_EPS finchfsd -t $NUM_THREADS -c /scr -s $FINCH_DB_SIZE -v debug &
    sleep 5 # wait for finchfsd to start

.. warning::

    We must set ``UCX_IB_MLX5_DEVX``, ``UCX_IB_REG_METHODS``, and ``UCX_NUM_EPS``.
    ``UCX_IB_MLX5_DEVX`` and ``UCX_IB_REG_METHODS`` are for enabling the RDMA on demand paging and disabling rcache because there is a problem with it.
    ``UCX_NUM_EPS`` is for setting the number of endpoints and use `DC transport <https://www.openfabrics.org/images/eventpresos/workshops2014/DevWorkshop/presos/Monday/pdf/05_DC_Verbs.pdf>`_.

When we use pmemkv backend with devdax mode, 
we need to create namespaces for the number of threads, by `ndctl <https://docs.pmem.io/ndctl-user-guide/ndctl-man-pages/ndctl-create-namespace>`_.
We specify the ``-c /dev/dax0.%d`` option to ``finchfsd``, then ``finchfsd`` use ``/dev/dax0.0``, ``/dev/dax0.1``, ..., ``/dev/dax0.$((NUM_THREADS - 1))``.

.. code-block:: bash

    mpirun -np $NUM_NODES --map-by ppr:1:node:PE=$NUM_THREADS -x UCX_IB_MLX5_DEVX -x UCX_IB_REG_METHODS -x UCX_NUM_EPS finchfsd -t $NUM_THREADS -c /dev/dax0.%d -s $FINCH_DB_SIZE -v debug &

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
