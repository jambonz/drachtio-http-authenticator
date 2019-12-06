const request = require('request');
const nonce = require('nonce')();
const parseUri = require('drachtio-srf').parseUri;
const debug = require('debug')('drachtio:http-authenticator');

function parseAuthHeader(hdrValue) {
  const pieces = { scheme: 'digest'} ;
  ['username', 'realm', 'nonce', 'uri', 'algorithm', 'response', 'qop', 'nc', 'cnonce', 'opaque']
    .forEach((tok) => {
      const re = new RegExp(`[,\\s]{1}${tok}="?(.+?)[",]`) ;
      const arr = re.exec(hdrValue) ;
      if (arr) {
        pieces[tok] = arr[1];
        if (pieces[tok] && pieces[tok] === '"') pieces[tok] = '';
      }
    }) ;

  pieces.algorithm = pieces.algorithm || 'MD5' ;

  // this is kind of lame...nc= (or qop=) at the end fails the regex above,
  // should figure out how to fix that
  if (!pieces.nc && /nc=/.test(hdrValue)) {
    const arr = /nc=(.*)$/.exec(hdrValue) ;
    if (arr) {
      pieces.nc = arr[1];
    }
  }
  if (!pieces.qop && /qop=/.test(hdrValue)) {
    const arr = /qop=(.*)$/.exec(hdrValue) ;
    if (arr) {
      pieces.qop = arr[1];
    }
  }

  // check mandatory fields
  ['username', 'realm', 'nonce', 'uri', 'response'].forEach((tok) => {
    if (!pieces[tok]) throw new Error(`missing authorization component: ${tok}`);
  }) ;
  debug(`parsed header: ${JSON.stringify(pieces)}`);
  return pieces ;
}

function respondChallenge(req, res) {
  const nonceValue = nonce();
  const uri = parseUri(req.uri);
  const headers = {
    'WWW-Authenticate': `Digest realm="${uri.host}", algorithm=MD5, qop="auth", nonce="${nonceValue}"`
  };
  debug('sending a 401 challenge');
  res.send(401, {headers});
}

function digestChallenge(obj, logger) {
  let dynamicCallback;
  if (!logger) logger = {info: () => {}, error: () => {}};
  if (typeof obj === 'string') obj = {uri: obj};
  else if (typeof obj === 'function') dynamicCallback = obj;

  return async(req, res, next) => {
    let auth, uri;

    if (dynamicCallback) {
      const sipUri = parseUri(req.uri);
      try {
        const obj = await dynamicCallback(sipUri.host);
        auth = obj.auth;
        uri = obj.uri || obj.url;
      } catch (err) {
        logger.info(`unknown domain ${sipUri.host}, rejecting with 403`);
        // TODO: allow callee to signal blacklist this source IP ??
        return res.send(403);
      }
    }
    else {
      uri = obj.uri || obj.url;
      auth = obj.auth;
    }

    // challenge requests without credentials
    if (!req.has('Authorization')) return respondChallenge(req, res);

    const pieces = req.authorization = parseAuthHeader(req.get('Authorization'));
    debug(`parsed authorization header: ${JSON.stringify(pieces)}`);
    request({
      uri,
      auth,
      method: 'POST',
      json: true,
      body: Object.assign({method: req.method}, pieces)
    }, (err, response, body) => {
      if (err) {
        debug(`Error from calling auth callback: ${err}`);
        return next(err);
      }
      debug(`received ${response.statusCode} with body ${JSON.stringify(body)}`);
      if (response.statusCode !== 200) {
        debug(`auth callback returned a non-success response: ${response.statusCode}`);
        return res.send(500);
      }
      if (body.status != 'ok') {
        // TODO: deal with blacklist requests
        res.send(403);
      }
      if (typeof body.expires === 'number') req.authorization.expires = body.expires;
      next();
    });
  };
}

module.exports = digestChallenge;
