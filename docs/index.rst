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

.. toctree::
   :maxdepth: 3
   :caption: API Reference

   slimhttpd/HTTP_SERVER