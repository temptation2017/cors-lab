'use strict';

var C = require('./cors.js');
var failed = 0;
var passed = 0;

function check(name, got, expected) {
  var ok = got === expected;
  if (ok) {
    passed++;
    return;
  }
  failed++;
  console.error('FAIL', name, '\n  got:     ', JSON.stringify(got), '\n  expected:', JSON.stringify(expected));
}

function checkOk(name, cond) {
  check(name, !!cond, true);
}

function analyze(partial) {
  return C.analyze(partial);
}

function checkIds(name, result, id, level) {
  var item = result.checks.filter(function (c) { return c.id === id; })[0];
  checkOk(name + ' has ' + id, !!item);
  if (item) check(name + ' ' + id + ' level', item.level, level);
}

// --- header parsing ---
var parsed = C.parseHeaders([
  'HTTP/1.1 204 No Content',
  'Access-Control-Allow-Origin: https://app.example.com',
  'Access-Control-Allow-Methods: GET, POST',
  'X-Request-Id: a',
  'X-Request-Id: b'
].join('\n'));
check('status', parsed.status, 204);
check('acao', parsed.map['access-control-allow-origin'].values[0], 'https://app.example.com');
check('duplicate join later', parsed.map['x-request-id'].values.length, 2);

var parsedFold = C.parseHeaders('X-Long: hello\n  world');
check('folded value', parsedFold.map['x-long'].values[0], 'hello world');

// --- origin ---
check('origin ok', C.originKind('https://app.example.com').ok, true);
check('origin port', C.originKind('http://127.0.0.1:8080').ok, true);
check('origin null', C.originKind('null').ok, true);
check('origin slash', C.originKind('https://app.example.com/').ok, false);
check('origin path', C.originKind('https://app.example.com/app').ok, false);
check('origin empty', C.originKind('').ok, false);

// --- classification ---
var simple = C.classifyRequest('GET', [{ name: 'Accept', value: 'application/json' }]);
check('simple get', simple.simple, true);

var jsonPost = C.classifyRequest('POST', [{ name: 'Content-Type', value: 'application/json' }]);
check('json post preflight', jsonPost.preflightNeeded, true);

var formPost = C.classifyRequest('POST', [{ name: 'Content-Type', value: 'application/x-www-form-urlencoded' }]);
check('form post simple', formPost.simple, true);

var put = C.classifyRequest('PUT', []);
check('put preflight', put.preflightNeeded, true);

var auth = C.classifyRequest('GET', [{ name: 'Authorization', value: 'Bearer abc' }]);
check('authorization preflight', auth.preflightNeeded, true);

var cookieOnly = C.classifyRequest('GET', [{ name: 'Cookie', value: 'sid=1' }]);
check('cookie does not trigger preflight', cookieOnly.simple, true);

// --- samples ---
var s1 = analyze(C.samples.simpleOk);
check('simpleOk verdict', s1.verdict, 'allow');
check('simpleOk mode', s1.mode, 'actual');
check('simpleOk simple', s1.classification.simple, true);

var s2 = analyze(C.samples.jsonPreflightOk);
check('json preflight verdict', s2.verdict, 'allow');
check('json preflight mode', s2.mode, 'preflight');
checkIds('json', s2, 'methods', 'pass');
checkIds('json', s2, 'headers', 'pass');
checkIds('json', s2, 'status', 'pass');
checkIds('json', s2, 'vary', 'pass');

var s3 = analyze(C.samples.credStar);
check('cred star verdict', s3.verdict, 'block');
check('cred star credentialed', s3.credentialed, true);
checkIds('cred star', s3, 'acao', 'fail');

var s4 = analyze(C.samples.originMismatch);
check('mismatch verdict', s4.verdict, 'block');
checkIds('mismatch', s4, 'acao', 'fail');

var s5 = analyze(C.samples.authStar);
check('auth star verdict', s5.verdict, 'block');
checkIds('auth star', s5, 'headers', 'fail');

var s6 = analyze(C.samples.fileNull);
check('file null verdict', s6.verdict, 'allow');
check('file null origin kind', s6.origin.kind, 'null');

// --- credentialed exact origin ---
var credOk = analyze({
  origin: 'https://app.example.com',
  method: 'GET',
  credentialed: true,
  requestHeadersText: '',
  responseText: [
    'HTTP/1.1 200 OK',
    'Access-Control-Allow-Origin: https://app.example.com',
    'Access-Control-Allow-Credentials: true',
    'Vary: Origin',
    'Content-Type: application/json'
  ].join('\n')
});
check('cred exact verdict', credOk.verdict, 'allow');

// ACAC must be literal true
var credCase = analyze({
  origin: 'https://app.example.com',
  method: 'GET',
  credentialed: true,
  responseText: [
    'Access-Control-Allow-Origin: https://app.example.com',
    'Access-Control-Allow-Credentials: TRUE'
  ].join('\n')
});
check('acac case verdict', credCase.verdict, 'block');

// multiple origins invalid
var multi = analyze({
  origin: 'https://app.example.com',
  method: 'GET',
  responseText: 'Access-Control-Allow-Origin: https://app.example.com, https://admin.example.com'
});
check('multi origin verdict', multi.verdict, 'block');

// trailing slash mismatch
var slash = analyze({
  origin: 'https://app.example.com',
  method: 'GET',
  responseText: 'Access-Control-Allow-Origin: https://app.example.com/'
});
check('slash origin verdict', slash.verdict, 'block');

// missing ACAO
var missing = analyze({
  origin: 'https://app.example.com',
  method: 'GET',
  responseText: 'Content-Type: text/plain'
});
check('missing acao', missing.verdict, 'block');

// preflight method missing
var noMethod = analyze({
  origin: 'https://app.example.com',
  method: 'OPTIONS',
  requestHeadersText: 'Access-Control-Request-Method: PUT',
  responseText: [
    'HTTP/1.1 204 No Content',
    'Access-Control-Allow-Origin: https://app.example.com',
    'Access-Control-Allow-Methods: GET, POST'
  ].join('\n')
});
check('put not allowed', noMethod.verdict, 'block');
checkIds('put', noMethod, 'methods', 'fail');

// Allow-Methods * without credentials
var starMethod = analyze({
  origin: 'https://app.example.com',
  method: 'OPTIONS',
  requestHeadersText: 'Access-Control-Request-Method: PUT',
  responseText: [
    'HTTP/1.1 204 No Content',
    'Access-Control-Allow-Origin: *',
    'Access-Control-Allow-Methods: *'
  ].join('\n')
});
check('star method allow', starMethod.verdict, 'allow');

// Allow-Methods * with credentials
var starMethodCred = analyze({
  origin: 'https://app.example.com',
  method: 'OPTIONS',
  credentialed: true,
  requestHeadersText: 'Access-Control-Request-Method: PUT',
  responseText: [
    'HTTP/1.1 204 No Content',
    'Access-Control-Allow-Origin: https://app.example.com',
    'Access-Control-Allow-Credentials: true',
    'Access-Control-Allow-Methods: *'
  ].join('\n')
});
check('star method cred block', starMethodCred.verdict, 'block');

// Allow-Headers * with credentials should fail for custom header
var starHeadCred = analyze({
  origin: 'https://app.example.com',
  method: 'OPTIONS',
  credentialed: true,
  requestHeadersText: [
    'Access-Control-Request-Method: GET',
    'Access-Control-Request-Headers: x-trace-id'
  ].join('\n'),
  responseText: [
    'HTTP/1.1 204 No Content',
    'Access-Control-Allow-Origin: https://app.example.com',
    'Access-Control-Allow-Credentials: true',
    'Access-Control-Allow-Methods: GET',
    'Access-Control-Allow-Headers: *'
  ].join('\n')
});
check('star header cred block', starHeadCred.verdict, 'block');

// Allow-Headers * without credentials, custom header ok, but not Authorization
var starHeadOk = analyze({
  origin: 'https://app.example.com',
  method: 'OPTIONS',
  requestHeadersText: [
    'Access-Control-Request-Method: GET',
    'Access-Control-Request-Headers: x-trace-id'
  ].join('\n'),
  responseText: [
    'HTTP/1.1 204 No Content',
    'Access-Control-Allow-Origin: *',
    'Access-Control-Allow-Methods: GET',
    'Access-Control-Allow-Headers: *'
  ].join('\n')
});
check('star header no cred allow', starHeadOk.verdict, 'allow');

// preflight non-2xx
var pre404 = analyze({
  origin: 'https://app.example.com',
  method: 'OPTIONS',
  requestHeadersText: 'Access-Control-Request-Method: POST',
  responseText: [
    'HTTP/1.1 404 Not Found',
    'Access-Control-Allow-Origin: https://app.example.com',
    'Access-Control-Allow-Methods: POST, OPTIONS',
    'Access-Control-Allow-Headers: Content-Type'
  ].join('\n')
});
check('preflight 404 block', pre404.verdict, 'block');
checkIds('pre404', pre404, 'status', 'fail');

// actual JSON POST without preflight-looking response
var actualJson = analyze({
  origin: 'https://app.example.com',
  method: 'POST',
  requestHeadersText: 'Content-Type: application/json',
  responseText: [
    'HTTP/1.1 200 OK',
    'Access-Control-Allow-Origin: https://app.example.com',
    'Content-Type: application/json'
  ].join('\n')
});
check('actual json flagged', actualJson.verdict, 'block');
checkIds('actual json', actualJson, 'missing-preflight', 'fail');

// cookie header implies credentialed
var cookieImplied = analyze({
  origin: 'https://app.example.com',
  method: 'GET',
  credentialed: false,
  requestHeadersText: 'Cookie: sid=demo',
  responseText: 'Access-Control-Allow-Origin: *\nContent-Type: text/plain'
});
check('cookie implies cred', cookieImplied.credentialed, true);
check('cookie + star block', cookieImplied.verdict, 'block');

// expose headers: X-Request-Id hidden unless exposed
var expose = analyze({
  origin: 'https://app.example.com',
  method: 'GET',
  responseText: [
    'HTTP/1.1 200 OK',
    'Access-Control-Allow-Origin: *',
    'Content-Type: application/json',
    'X-Request-Id: req-1'
  ].join('\n')
});
checkOk('content-type readable', expose.readableHeaders.indexOf('Content-Type') !== -1);
checkOk('x-request-id hidden', expose.hiddenHeaders.indexOf('X-Request-Id') !== -1);

var exposeOk = analyze({
  origin: 'https://app.example.com',
  method: 'GET',
  responseText: [
    'HTTP/1.1 200 OK',
    'Access-Control-Allow-Origin: *',
    'Access-Control-Expose-Headers: X-Request-Id',
    'Content-Type: application/json',
    'X-Request-Id: req-1'
  ].join('\n')
});
checkOk('exposed readable', exposeOk.readableHeaders.indexOf('X-Request-Id') !== -1);

// Vary hint when ACAO is concrete origin
var noVary = analyze({
  origin: 'https://app.example.com',
  method: 'GET',
  responseText: 'Access-Control-Allow-Origin: https://app.example.com\nContent-Type: text/plain'
});
check('no vary still allow', noVary.verdict, 'allow');
checkIds('no vary', noVary, 'vary', 'warn');

// markdown contains verdict
var md = C.toMarkdown(s3);
checkOk('markdown has block', md.indexOf('预计拦截') !== -1);
checkOk('markdown has origin', md.indexOf('https://app.example.com') !== -1);

// Private Network Access
var pna = analyze({
  origin: 'https://app.example.com',
  method: 'OPTIONS',
  requestHeadersText: [
    'Access-Control-Request-Method: GET',
    'Access-Control-Request-Private-Network: true'
  ].join('\n'),
  responseText: [
    'HTTP/1.1 204 No Content',
    'Access-Control-Allow-Origin: https://app.example.com',
    'Access-Control-Allow-Methods: GET'
  ].join('\n')
});
check('pna missing block', pna.verdict, 'block');
checkIds('pna', pna, 'pna', 'fail');

var pnaOk = analyze({
  origin: 'https://app.example.com',
  method: 'OPTIONS',
  requestHeadersText: [
    'Access-Control-Request-Method: GET',
    'Access-Control-Request-Private-Network: true'
  ].join('\n'),
  responseText: [
    'HTTP/1.1 204 No Content',
    'Access-Control-Allow-Origin: https://app.example.com',
    'Access-Control-Allow-Methods: GET',
    'Access-Control-Allow-Private-Network: true'
  ].join('\n')
});
check('pna ok', pnaOk.verdict, 'allow');

if (failed) {
  console.error('Failed:', failed, 'Passed:', passed);
  process.exit(1);
}
console.log('All ' + passed + ' checks passed.');
