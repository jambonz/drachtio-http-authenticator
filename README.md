# drachtio-http-authenticator

drachtio middleware that delegates sip authentication to an http api.  This allows, for instance, a multi-tenant sip application server to delegate authentication to a customer api.

The middleware-returning function needs to be invoked with the HTTP URL to call and, optionally, a username and password if HTTP Basic Authentication is being used to protect the endpoint.  

An HTTP POST will be made to the specified URL with a JSON body containing the sip method and the components from the Authorization header.  The HTTP server should return a status code of 200 in all cases, containing a JSON body with instructions on whether to admit the request.

To admit the request, send a 200 response with a `status` of `ok`, e.g.
```
{"status": "ok"}
```
To deny the request, send a 200 response with a `status` of `fail`.  Optionally, a fail response may include a `msg` attribute and/or an `action` attribute with value `block`.  The latter will cause the IP address that sent the request to be blocked from sending further traffic to the system, e.g.:
```
{"status": "fail"}
```
or
```
{"status": "fail", "msg": "unknown user"}
```
```
{"status": "fail", "action": "block"}
```


Additionally, for admitted requests, the middleware adds a `req.authorization` attribute which references an object containing the parsed elements of the sip Authorization header.
```
const authenticator = require('drachtio-http-authenticator')({
  url: 'https://example.com/auth',
  auth: {
    username: 'foo',
    password: 'bar'
  }
});

srf.use('invite', authenticator);
```