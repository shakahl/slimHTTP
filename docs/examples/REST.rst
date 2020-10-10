.. _REST:

REST
====

| By leveraging `@app.route` we can setup mock endpoints.
| These endpoints will get one parameter, the :class:`~slimHTTP.HTTP_REQUEST` object.

.. warning::

    The following example is for non-vhost entries. This is useful for simpel setups.
    Read below for a `REST`_ Vhost option.

.. code-block:: py

    @http.route('/')
    def main_entry(request):
        print(request.headers)

        return request.build_headers() + b'<html><body>Test body</body></html>

This is a minimal example of how to respond with some default basic headers and a default content.

Methods and headers
-------------------

| Unlike many other frameworks, slimHTTP does not currently support `method='POST'` filtering
| in the `@http.route` functionality. Instead, the `method` is given or found in `request.method`
| in each request object *(or for the raw request data, also in `request.headers[b"METHOD"]`)*.

An example to react to `PUT` requests:

.. code-block:: py

    @http.route('/')
    def main_entry(request):
        if request.method == 'PUT':
            print('We got a PUT request with headers:', request.headers)

.. _REST
REST with Virtual Hosts
-----------------------

| When creating virtual hosts in your configuration, the router needs to know
| that you want to insert a route to a specific virtual host. Which can be done
| by doing the following:

.. warning::

    You first need to grab the `http` instance object, since virtual host entry-points 
    are usually defined in a separate file from where the `http` variable was created.

    This example also shows you how to grab that instance.

.. code-block:: py

    import slimHTTP
    
    http = slimHTTP.instances[':80']
    
    @http.route('/', vhost='example.com')
    def main_entry(request):
        print(request.headers)

        return request.build_headers() + b'<html><body>Test body</body></html>

| This example will not trigger on the default hosted site, but instead only trigger
| on the web-root of `example.com` in this example.

REST with JSON
--------------

| By default, slimHTTP will *try* to parse incoming data labled with `Content-Type: application/json` as JSON.
| But ultimately it's up to the developer to verify.

To convert and work with the request data, you could do something along the lines of:

.. code-block:: py

    @http.route('/')
    def main_entry(request):
        data = json.loads(request.payload.decode('UTF-8'))
        print(data['key'])

And to respond, you could build ontop of it by doing:

.. code-block:: py

    @http.route('/')
    def main_entry(request):
        data = json.loads(request.payload.decode('UTF-8'))
        print(data['key'])
        
        return request.build_headers({'Content-Type' : 'application/json'}) + bytes(json.dumps({"key" : "a value"}, 'UTF-8')

Which would instruct slimHTTP to build a basic header response with one additional header, the `Content-Type` and utilize `json.dumps <https://docs.python.org/3/library/json.html#json.dumps>`_ to dump a dictionary structure.

.. note::

    | But a more future proof way would be to use the :ref:`~slimHTTP.HTTP_RESPONSE` object as a return value.
    | This enables you to avoid building the headers yourself as well as concatinate the payload and format it.

    .. code-block::py

        @http.route('/')
        def main_entry(request):
            data = json.loads(request.payload.decode('UTF-8'))
            print(data['key'])

            return slimHTTP.HTTP_RESPONSE(ret_code=200,
                                headers={'Content-Type' : 'application/json'},
                                payload={'ip' : request.CLIENT_IDENTITY.address, 'country' : 'SWEDEN'})