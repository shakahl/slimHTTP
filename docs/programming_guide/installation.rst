Installation
============

.. note:: These instructions apply to slimHTTP |version|.

slimHTTP is a pure python library, so no special steps are required for
installation. You can install it in a variety of ways, or simply copy the
`slimHTTP` folder directly into your project.

You can clone the repository using **git**:

.. code-block:: sh

    git clone https://github.com/Torxed/slimHTTP.git


**To enable WebSockets**, you'll need to firstly handle `Connection: Upgrade` request headers and then supply a appropriate upgrade module. More on this in `Enabling WebSockets <programming_guide/enabling_websockets>`_.


Running the examples
--------------------

The source code archives include examples. Archives are
`available on Github <https://github.com/Torxed/slimHTTP/releases/>`_:

.. code-block:: sh

    unzip slimHTTP-x.x.x.zip
    cd slimHTTP-x.x.x
    python examples/http_server.py


As mentioned above, you can also clone the repository using Git:

.. code-block:: sh

    git clone https://github.com/Torxed/slimHTTP.git
    cd slimHTTP
    python examples/http_server.py
