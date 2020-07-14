# <img src="https://github.com/Torxed/slimHTTP/raw/master/docs/_static/slimHTTP.png" alt="drawing" width="200"/>
A simple, minimal and flexible Python HTTP server.<br>
Usecases may be: REST, WebSocket¹, ~reverse proxy~ and static file delivery.

 * slimHTTP [documentation](https://slimhttp.readthedocs.io/en/master)
 * slimHTTP [discord](https://discord.gg/CMjZbwR) server

## Supports

 * REST routes *(`@http.route('/some/endpoint')`)*
 * websockets if `@http.on_upgrade` is defined using [spiderWeb](https://github.com/Torxed/spiderWeb) ¹
 * Static file emulation with `@http.route('/example.html')`
 * vhosts
 * ssl/tls
 * reverse proxy
 * python module proxy
 * No threading or threads used *(fully relies on `epoll()` (`select()` on Windows))*
 * flexible configuration in runtime via `@http.configuration`

## Minimal example

```py
import slimHTTP

http = slimHTTP.host(slimHTTP.HTTP)
http.run()
```

Serves any files under `/srv/http` by default in `HTTP` mode.

## Footnote

It's not pretty down here. But it'll do in a pinch.
