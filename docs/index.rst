slimHTTP Documentation
======================

**slimHTTP** is a simple, minimal and flexible HTTP server. It supports modules for parsing WebSocket [1]_ traffic as well as REST api routes.

Some of the features of pyglet are:

* **No external dependencies or installation requirements.** Runs without any external requirements or installation processes.

* **Single threaded.** slimHTTP takes advantage of `select.epoll()` *(`select.select` on Windows)* to achieve blazing speeds without threading the service.

.. [1] WebSocket support is provided by using a `@app.on_upgrade` hook and parsed by a separate library, like spiderWeb_

.. _spiderWeb: https://github.com/Torxed/spiderWeb

.. toctree::
   :maxdepth: 3
   :caption: Programming Guide

   programming_guide/installation
   programming_guide/quickstart
   programming_guide/examples
   programming_guide/configuration
   programming_guide/upgrade_mechanics

.. toctree::
   :maxdepth: 3
   :caption: API Reference

   slimhttpd/host
   slimhttpd/HTTP_SERVER
   slimhttpd/HTTPS_SERVER
   slimhttpd/HTTP_REQUEST
   slimhttpd/HTTP_RESPONSE
   slimhttpd/ROUTE_HANDLER
   slimhttpd/HTTP_CLIENT_IDENTITY
   slimhttpd/Events

.. toctree::
   :maxdepth: 3
   :caption: Internal Functions

   slimhttpd/handle_py_request
   slimhttpd/get_file
   slimhttpd/CertManager
   slimhttpd/slimHTTP_Error
   slimhttpd/ConfError
   slimhttpd/NotYetImplemented
   slimhttpd/UpgradeIssue