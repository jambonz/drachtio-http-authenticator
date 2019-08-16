# drachtio-http-authenticator

drachtio middleware that delegates sip authentication to an http api.  This allows, for instance, a multi-tenant sip application server to delegate authentication to a customer api.

The middleware-returning function needs to be invoked with the HTTP URL to call and, optionally, a username and password if HTTP Basic Authentication is being used to protect the endpoint.  

An HTTP POST will be made to the specified URL with a JSON body containing the sip method and the components from the Authorization header.  An HTTP response code of 200 indicates that the SIP request should be admitted; any other response code will cause a 403 Forbidden sip response to the incoming request.

Additionally, the middleware adds a `req.authorization` attribute which references an object containing the parsed elements of the sip Authorization header.
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