.. _quickstart:

Starting a web-server
=====================

.. note:: slimHTTP does support TLS(HTTPS), but these examples will stick to plain old HTTP to avoid confusion.


Hello, World
------------

The simplest of use cases, where you just want something up and running would be to present any HTML files in a folder. There's also more examples in `examples/` within the **git** repository.

Begin by importing :mod:`slimhttpd.py` which is the one and only file you'll need.::

    import slimhttpd

Call :py:func:`~slimhttpd.host` with the mode that you wish to run it in, the default is :py:attr:`slimhttpd.HTTP` which enables a HTTP server on :py:attr:`address` `0.0.0.0` and a :py:attr:`port` of `80`::

    http = slimhttpd.host(slimhttpd.HTTP)

This is in theory everything you need in order to host a default web server, the last thing we'll need tho is to poll for events. Essentially creating a main loop for our webserver to keep it alive.::

    while 1:
        for event, *event_data in http.poll():
            pass

Different :ref:`slimhttpd-events` are generated, so read more in detail if you need to trigger certain things at different stages of a client request process.

Customising the web root directory
----------------------------------

By default, the web server hosts anything in `./`, which is not ideal - but works for test purposes. For a better lab environment, redirecting to a folder is preferred. To do this, there's a configuration override annotation that can be used.::

    @http.configuration
    def config():
        return {
            "web_root" : "/srv/http",
            "index" : ["index.html", "index.py"]
        }

This will reconfigure `slimhttpd` to use the new configuration assuming it passes :py:meth:`~slimhttpd.HTTP_SERVER.check_config`. Otherwise a :py:class:`~slimhttpd.ConfError` will be issued and the previous configuration remains.

This also reconfigures the default index `index.html` to point to a series of index files which `slimhttpd` will attempt to locate if no specific file was given in the client request.

Adding REST API routes
----------------------

.. note:: `slimHTTP` supports adding static routes, something which can be utilized in order to achieve `REST <https://en.wikipedia.org/wiki/Representational_state_transfer>`_ functionality in the simplest possible meaning of the term.

For this example, we'll create a endpoint called `/auth/login`. This endpoint will respond with a simple JSON response telling the client that the status is successful.::

    @http.route('/auth/login')
    def handle_login(request):
        return slimhttpd.HTTP_RESPONSE(headers={'Content-Type' : 'application/json'},
                                        payload={"status" : "successful"})

In this example, we simplify the building of headers and manually creating a valid `HTTP server response <https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol#Server_response>`_ - by using :py:class:`~slimhttpd.HTTP_RESPONSE`. But building data manually is fine too.

.. note:: :py:class:`~slimhttpd.HTTP_RESPONSE` will automatically convert the payload to a suitable transmission format based on the headers. No need to use `json.dumps` altho that works too.