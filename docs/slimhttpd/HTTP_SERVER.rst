slimhttpd
=========

.. rubric:: Submodules

.. toctree::
   :maxdepth: 1

   HTTP
   HTTPS
   imported_paths
   handle_py_request
   get_file

.. rubric:: Details

.. automodule:: slimhttpd

Classes
-------

.. autoclass:: HTTP_SERVER
  :show-inheritance:

  .. rubric:: Methods

  .. automethod:: log
  .. automethod:: check_config
  .. automethod:: unregister
  .. automethod:: default_config
  .. automethod:: configuration
  .. automethod:: GET
  .. automethod:: GET_func
  .. automethod:: REQUESTED_METHOD
  .. automethod:: local_file
  .. automethod:: allow
  .. automethod:: on_accept
  .. automethod:: on_accept_func
  .. automethod:: on_accept_callback
  .. automethod:: on_close
  .. automethod:: on_upgrade
  .. automethod:: on_upgrade_func
  .. automethod:: on_close_func
  .. automethod:: route
  .. automethod:: poll
  .. automethod:: do_the_dance
