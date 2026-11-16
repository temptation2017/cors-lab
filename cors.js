'use strict';

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.CorsLab = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  var SAFE_METHODS = { GET: 1, HEAD: 1, POST: 1 };
  var SAFE_CT = {
    'application/x-www-form-urlencoded': 1,
    'multipart/form-data': 1,
    'text/plain': 1
  };
  var SAFE_RESPONSE = {
    'cache-control': 1,
    'content-language': 1,
    'content-length': 1,
    'content-type': 1,
    'expires': 1,
    'last-modified': 1,
    'pragma': 1
  };
  // Forbidden / UA-controlled request headers: they do not trigger preflight.
  var FORBIDDEN_REQUEST = {
    'accept-charset': 1,
    'accept-encoding': 1,
    'access-control-request-headers': 1,
    'access-control-request-method': 1,
    'access-control-request-private-network': 1,
    'connection': 1,
    'content-length': 1,
    'cookie': 1,
    'cookie2': 1,
    'date': 1,
    'dnt': 1,
    'expect': 1,
    'host': 1,
    'keep-alive': 1,
    'origin': 1,
    'referer': 1,
    'te': 1,
    'trailer': 1,
    'transfer-encoding': 1,
    'upgrade': 1,
    'via': 1
  };

  function trim(s) {
    return String(s == null ? '' : s).replace(/^\s+|\s+$/g, '');
  }

  function splitList(value) {
    if (value == null || trim(value) === '') return [];
    return String(value).split(',').map(trim).filter(function (x) { return x.length > 0; });
  }

  function headerNameOk(name) {
    return /^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/.test(name);
  }

  function isForbiddenRequestHeader(name) {
    var n = name.toLowerCase();
    if (FORBIDDEN_REQUEST[n]) return true;
    if (n.indexOf('proxy-') === 0 || n.indexOf('sec-') === 0) return true;
    return false;
  }

  function parseHeaders(text) {
    var out = { status: null, statusText: '', raw: [], map: {} };
    var lines = String(text || '').replace(/^\uFEFF/, '').split(/\r?\n/);
    var i = 0;
    if (lines.length && /^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s+(.*))?$/i.test(trim(lines[0]))) {
      var m = trim(lines[0]).match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s+(.*))?$/i);
      out.status = parseInt(m[1], 10);
      out.statusText = m[2] ? trim(m[2]) : '';
      i = 1;
    }
    var pending = null;
    for (; i < lines.length; i++) {
      var line = lines[i];
      if (line === '') continue;
      if (pending && /^[ \t]/.test(line)) {
        pending.value += ' ' + trim(line);
        continue;
      }
      var cut = line.indexOf(':');
      if (cut <= 0) continue;
      var name = trim(line.slice(0, cut));
      var value = trim(line.slice(cut + 1));
      if (!name) continue;
      pending = { name: name, value: value };
      out.raw.push(pending);
    }
    out.raw.forEach(function (h) {
      var key = h.name.toLowerCase();
      if (!out.map[key]) out.map[key] = { name: h.name, values: [] };
      out.map[key].values.push(h.value);
    });
    return out;
  }

  function headerValue(parsed, name) {
    var h = parsed.map[name.toLowerCase()];
    if (!h) return null;
    return h.values.join(', ');
  }

  function parseRequestHeaders(text) {
    var parsed = parseHeaders(text);
    return parsed.raw.map(function (h) {
      return { name: h.name, value: h.value };
    });
  }

  function originKind(origin) {
    var o = trim(origin);
    if (o === '') return { ok: false, value: '', error: '缺少 Origin' };
    if (o === 'null') return { ok: true, value: 'null', kind: 'null' };
    // RFC 6454 serialized origin: scheme://host[:port]  (no path, no trailing slash)
    var m = o.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]+)$/);
    if (!m) {
      var hint = /\/$/.test(o) ? 'Origin 不能带路径或末尾斜杠' : '不是合法的 Origin（应为 scheme://host[:port]，或 null）';
      return { ok: false, value: o, error: hint };
    }
    return { ok: true, value: o, kind: 'tuple', scheme: m[1].toLowerCase(), host: m[2] };
  }

  function isSafelistedContentType(value) {
    var essence = trim(value).split(';')[0].toLowerCase();
    return !!SAFE_CT[essence];
  }

  function isSafelistedRange(value) {
    return /^bytes=[0-9]+-$/.test(trim(value));
  }

  function isSafelistedRequestHeader(name, value) {
    var n = name.toLowerCase();
    if (n === 'accept' || n === 'accept-language' || n === 'content-language') return true;
    if (n === 'content-type') return isSafelistedContentType(value);
    if (n === 'range') return isSafelistedRange(value);
    return false;
  }

  function classifyRequest(method, requestHeaders) {
    var m = trim(method) || 'GET';
    var methodUpper = m.toUpperCase();
    var reasons = [];
    if (!SAFE_METHODS[methodUpper]) {
      reasons.push({ code: 'method', text: '方法 ' + methodUpper + ' 不是简单方法（GET / HEAD / POST）' });
    }
    var author = [];
    requestHeaders.forEach(function (h) {
      if (isForbiddenRequestHeader(h.name)) return;
      author.push(h);
      if (!isSafelistedRequestHeader(h.name, h.value)) {
        var extra = '';
        if (h.name.toLowerCase() === 'content-type') {
          extra = '（' + trim(h.value).split(';')[0] + ' 会触发预检；表单三类 MIME 才算简单）';
        } else if (h.name.toLowerCase() === 'authorization') {
          extra = '（Authorization 一定触发预检，且 * 覆盖不了它）';
        }
        reasons.push({
          code: 'header',
          header: h.name,
          text: '请求头 ' + h.name + ' 不是 CORS 安全列表头' + extra
        });
      }
    });
    return {
      method: methodUpper,
      simple: reasons.length === 0,
      preflightNeeded: reasons.length > 0,
      reasons: reasons,
      authorHeaders: author
    };
  }

  function looksLikePreflightResponse(parsed) {
    return !!(headerValue(parsed, 'access-control-allow-methods') ||
      headerValue(parsed, 'access-control-allow-headers') ||
      headerValue(parsed, 'access-control-max-age') ||
      headerValue(parsed, 'access-control-allow-private-network'));
  }

  function allowOriginCheck(requestOrigin, acao, credentialed) {
    if (acao == null || trim(acao) === '') {
      return {
        ok: false,
        title: '没有 Access-Control-Allow-Origin',
        detail: '跨源响应必须带上该头，否则浏览器会拦截读取（预检也会失败）。'
      };
    }
    var raw = acao;
    // Multiple ACAO values are invalid (some servers join origins with commas).
    var parts = splitList(raw);
    if (parts.length > 1) {
      return {
        ok: false,
        title: 'Access-Control-Allow-Origin 不能写多个源',
        detail: '当前值是「' + raw + '」。规范只允许单个源或 *。需要按请求的 Origin 动态回显，并加上 Vary: Origin。'
      };
    }
    var value = trim(raw);
    if (value === '*') {
      if (credentialed) {
        return {
          ok: false,
          title: '携带凭证时不能使用 Access-Control-Allow-Origin: *',
          detail: 'withCredentials / credentials: "include" 时，必须回显精确的 Origin，并加上 Access-Control-Allow-Credentials: true。'
        };
      }
      return {
        ok: true,
        title: 'Access-Control-Allow-Origin 为 *',
        detail: '未携带凭证时，* 允许任意源读取。'
      };
    }
    if (value === 'null') {
      if (requestOrigin === 'null') {
        return {
          ok: true,
          warn: true,
          title: '允许了 Origin: null',
          detail: '规范上匹配，但 null 来源很常见于沙箱 iframe、data: 或本地 file://，允许它等于对很多意料之外的页面开放，通常不建议。'
        };
      }
      return {
        ok: false,
        title: 'Access-Control-Allow-Origin: null 与请求 Origin 不一致',
        detail: '请求 Origin 是「' + requestOrigin + '」。'
      };
    }
    if (value === requestOrigin) {
      return {
        ok: true,
        title: 'Access-Control-Allow-Origin 与 Origin 一致',
        detail: value
      };
    }
    var hint = '';
    if (value === requestOrigin + '/' || requestOrigin === value + '/') {
      hint = ' Origin 和该头都不能带路径；末尾斜杠会导致匹配失败。';
    } else if (value.toLowerCase() === String(requestOrigin).toLowerCase()) {
      hint = ' 大小写也必须一致（主机名虽会规范化，但建议完全按请求头回显）。';
    }
    return {
      ok: false,
      title: 'Access-Control-Allow-Origin 与 Origin 不一致',
      detail: '请求是「' + requestOrigin + '」，响应是「' + value + '」。' + hint
    };
  }

  function credentialsCheck(credentialed, acac) {
    if (!credentialed) {
      if (acac && trim(acac).toLowerCase() === 'true') {
        return {
          ok: true,
          warn: true,
          title: '响应声明了 Allow-Credentials: true，但这次请求未携带凭证',
          detail: '这不会单独导致失败；若实际会带 Cookie，请把左侧「携带凭证」打开后再看一次。'
        };
      }
      return {
        ok: true,
        title: '未携带凭证',
        detail: '不需要 Access-Control-Allow-Credentials。'
      };
    }
    if (!acac || trim(acac) !== 'true') {
      return {
        ok: false,
        title: '携带凭证时必须有 Access-Control-Allow-Credentials: true',
        detail: acac == null || trim(acac) === ''
          ? '响应里没有这个头。'
          : '当前值是「' + acac + '」，只有小写字面量 true 有效（不能是 TRUE 或 1）。'
      };
    }
    return {
      ok: true,
      title: 'Access-Control-Allow-Credentials: true',
      detail: '已声明允许携带 Cookie / 客户端证书。'
    };
  }

  function methodsAllowed(requestedMethod, allowMethods, credentialed) {
    var list = splitList(allowMethods);
    if (allowMethods == null || list.length === 0) {
      // Fetch: if missing, the request method in ACR-Method is not allowed
      // (except that some browsers treat the method of the preflight itself? No.)
      return {
        ok: false,
        title: '没有 Access-Control-Allow-Methods',
        detail: '预检响应必须列出允许的方法，或在非凭证请求里使用 *。请求方法是 ' + requestedMethod + '。'
      };
    }
    var hasStar = list.indexOf('*') !== -1;
    if (hasStar) {
      if (credentialed) {
        return {
          ok: false,
          title: '携带凭证时 Access-Control-Allow-Methods: * 无效',
          detail: '必须显式写出方法名，例如 GET, POST, PUT, OPTIONS。'
        };
      }
      return {
        ok: true,
        title: 'Access-Control-Allow-Methods 为 *',
        detail: '未携带凭证时，* 允许任意方法（包括 ' + requestedMethod + '）。'
      };
    }
    var allowed = list.some(function (m) { return m.toUpperCase() === requestedMethod; });
    if (!allowed) {
      return {
        ok: false,
        title: 'Allow-Methods 未包含 ' + requestedMethod,
        detail: '当前列表：' + list.join(', ') + '。比较时方法名按大小写不敏感处理。'
      };
    }
    return {
      ok: true,
      title: 'Allow-Methods 包含 ' + requestedMethod,
      detail: list.join(', ')
    };
  }

  function headersAllowed(requestedNames, allowHeaders, credentialed) {
    var needed = [];
    var seen = {};
    requestedNames.forEach(function (n) {
      var key = n.toLowerCase();
      if (isForbiddenRequestHeader(n)) return;
      if (isSafelistedRequestHeader(n, 'text/plain') && key !== 'content-type' && key !== 'range') {
        // accept / accept-language / content-language never need to be listed
        return;
      }
      // content-type and range may still be non-safelisted depending on value;
      // the caller should pass only headers that triggered preflight, or we list all author headers
      // that are not always-safelisted names with safe values. We treat the given list as required.
      if (!seen[key]) {
        seen[key] = true;
        needed.push(n);
      }
    });
    if (needed.length === 0) {
      return {
        ok: true,
        title: '没有需要额外放行的请求头',
        detail: '预检可以不带 Access-Control-Allow-Headers。'
      };
    }
    var list = splitList(allowHeaders);
    if (allowHeaders == null || list.length === 0) {
      return {
        ok: false,
        title: '没有 Access-Control-Allow-Headers',
        detail: '预检要放行：' + needed.join(', ') + '。'
      };
    }
    var lower = list.map(function (x) { return x.toLowerCase(); });
    var hasStar = list.indexOf('*') !== -1;
    var missing = [];
    needed.forEach(function (n) {
      var key = n.toLowerCase();
      if (key === 'authorization') {
        // * never covers Authorization, even without credentials.
        if (lower.indexOf('authorization') === -1) missing.push(n + '（必须显式写出，* 覆盖不了）');
        return;
      }
      if (hasStar) {
        if (credentialed) {
          missing.push(n + '（携带凭证时 * 无效，必须显式写出）');
        }
        return;
      }
      if (lower.indexOf(key) === -1) missing.push(n);
    });
    if (missing.length) {
      return {
        ok: false,
        title: 'Allow-Headers 未完整放行请求头',
        detail: '缺：' + missing.join(', ') + '。当前列表：' + list.join(', ') + '。'
      };
    }
    return {
      ok: true,
      title: 'Allow-Headers 已放行所需请求头',
      detail: '需要放行：' + needed.join(', ') + '。'
    };
  }

  function exposedHeaders(parsed, credentialed) {
    var expose = headerValue(parsed, 'access-control-expose-headers');
    var names = Object.keys(parsed.map);
    var readable = [];
    var hidden = [];
    var list = splitList(expose);
    var lower = list.map(function (x) { return x.toLowerCase(); });
    var star = list.indexOf('*') !== -1;
    names.forEach(function (key) {
      var display = parsed.map[key].name;
      if (key.indexOf('access-control-') === 0) return;
      if (SAFE_RESPONSE[key]) {
        readable.push(display);
        return;
      }
      if (star && !credentialed && key !== 'authorization' && key !== 'set-cookie' && key !== 'set-cookie2') {
        readable.push(display);
        return;
      }
      if (lower.indexOf(key) !== -1) {
        readable.push(display);
        return;
      }
      hidden.push(display);
    });
    return { readable: readable, hidden: hidden, expose: expose };
  }

  function preflightStatusOk(status) {
    if (status == null) {
      return {
        ok: true,
        warn: true,
        title: '未提供预检状态码',
        detail: '规范要求预检响应是 2xx。如果实际是 404/405/500，浏览器会视预检失败。'
      };
    }
    if (status >= 200 && status < 300) {
      return {
        ok: true,
        title: '预检状态码 ' + status + ' 属于 2xx',
        detail: '符合 Fetch 对 CORS 预检成功的要求。'
      };
    }
    return {
      ok: false,
      title: '预检状态码 ' + status + ' 不是 2xx',
      detail: '即便带了 CORS 头，非 2xx 的预检也会失败。常见原因是 OPTIONS 没配路由，落到了 404 或 405。'
    };
  }

  function varyHint(parsed, acao) {
    if (!acao || trim(acao) === '*' || trim(acao) === '') return null;
    var vary = headerValue(parsed, 'vary');
    var hasOrigin = vary && splitList(vary).some(function (v) {
      return v.toLowerCase() === 'origin';
    });
    if (!hasOrigin) {
      return {
        ok: true,
        warn: true,
        title: '按 Origin 回显时建议加上 Vary: Origin',
        detail: '否则共享缓存（CDN、代理）可能把给 A 源的响应复用给 B 源。这不会让这次 CORS 检查失败，但会在缓存场景出错。'
      };
    }
    return {
      ok: true,
      title: '已包含 Vary: Origin',
      detail: vary
    };
  }

  function analyze(input) {
    input = input || {};
    var originInfo = originKind(input.origin);
    var method = trim(input.method) || 'GET';
    var credentialed = !!input.credentialed;
    var reqHeaders = Array.isArray(input.requestHeaders)
      ? input.requestHeaders
      : parseRequestHeaders(input.requestHeadersText || '');
    // Cookie in request headers implies credentialed
    reqHeaders.forEach(function (h) {
      var n = h.name.toLowerCase();
      if (n === 'cookie' || n === 'cookie2') credentialed = true;
    });
    var classified = classifyRequest(method, reqHeaders);
    var response = parseHeaders(input.responseText || '');
    var acao = headerValue(response, 'access-control-allow-origin');
    var acac = headerValue(response, 'access-control-allow-credentials');
    var allowMethods = headerValue(response, 'access-control-allow-methods');
    var allowHeaders = headerValue(response, 'access-control-allow-headers');
    var maxAge = headerValue(response, 'access-control-max-age');
    var acrMethod = null;
    var acrHeaders = [];
    reqHeaders.forEach(function (h) {
      var n = h.name.toLowerCase();
      if (n === 'access-control-request-method') acrMethod = trim(h.value).toUpperCase();
      if (n === 'access-control-request-headers') {
        splitList(h.value).forEach(function (x) { acrHeaders.push(x); });
      }
    });

    var assume = input.assume || 'auto';
    var methodUpper = classified.method;
    var isOptions = methodUpper === 'OPTIONS';
    var mode;
    if (assume === 'preflight' || assume === 'actual') {
      mode = assume;
    } else if (isOptions && (acrMethod || looksLikePreflightResponse(response))) {
      mode = 'preflight';
    } else if (classified.preflightNeeded && looksLikePreflightResponse(response)) {
      mode = 'preflight';
    } else if (classified.preflightNeeded && isOptions) {
      mode = 'preflight';
    } else {
      mode = 'actual';
    }

    var requestedMethod = mode === 'preflight'
      ? (acrMethod || (classified.preflightNeeded && !isOptions ? methodUpper : methodUpper))
      : methodUpper;
    if (mode === 'preflight' && !acrMethod && isOptions && !classified.preflightNeeded) {
      requestedMethod = methodUpper;
    }

    var neededHeaderNames;
    if (mode === 'preflight') {
      if (acrHeaders.length) {
        neededHeaderNames = acrHeaders;
      } else {
        neededHeaderNames = classified.reasons
          .filter(function (r) { return r.code === 'header' && r.header; })
          .map(function (r) { return r.header; });
        if (!neededHeaderNames.length) {
          neededHeaderNames = classified.authorHeaders
            .filter(function (h) { return !isSafelistedRequestHeader(h.name, h.value); })
            .map(function (h) { return h.name; });
        }
      }
    } else {
      neededHeaderNames = [];
    }

    var checks = [];
    function add(id, result) {
      var level = result.ok ? (result.warn ? 'warn' : 'pass') : 'fail';
      checks.push({
        id: id,
        ok: !!result.ok,
        level: level,
        title: result.title,
        detail: result.detail || ''
      });
    }

    if (!originInfo.ok) {
      checks.push({
        id: 'origin',
        ok: false,
        level: 'fail',
        title: 'Origin 无效',
        detail: originInfo.error
      });
    } else {
      checks.push({
        id: 'origin',
        ok: true,
        level: originInfo.kind === 'null' ? 'warn' : 'pass',
        title: originInfo.kind === 'null' ? 'Origin 是 null' : 'Origin 格式有效',
        detail: originInfo.kind === 'null'
          ? '常见于沙箱 iframe、data: URL 或本地 file:// 页面。许多站点不应放行 null。'
          : originInfo.value
      });
    }

    checks.push({
      id: 'class',
      ok: true,
      level: 'info',
      title: classified.simple ? '这是简单请求，浏览器不会先发预检' : '这是非简单请求，浏览器会先发 OPTIONS 预检',
      detail: classified.simple
        ? '方法与请求头都在 CORS 安全列表里。'
        : classified.reasons.map(function (r) { return r.text; }).join('；') + '。'
    });

    if (originInfo.ok) {
      add('acao', allowOriginCheck(originInfo.value, acao, credentialed));
      add('acac', credentialsCheck(credentialed, acac));
    }

    if (mode === 'preflight' && originInfo.ok) {
      add('status', preflightStatusOk(response.status));
      add('methods', methodsAllowed(requestedMethod, allowMethods, credentialed));
      add('headers', headersAllowed(neededHeaderNames, allowHeaders, credentialed));
      if (maxAge != null && trim(maxAge) !== '') {
        var ageNum = parseInt(trim(maxAge), 10);
        var ageDetail = trim(maxAge);
        if (!isNaN(ageNum)) {
          ageDetail = ageNum + ' 秒';
          if (ageNum > 86400) {
            ageDetail += '。注意：多数浏览器会把预检缓存上限压到 24 小时以内，填再大也未必生效。';
          }
        }
        checks.push({
          id: 'max-age',
          ok: true,
          level: 'info',
          title: 'Access-Control-Max-Age ' + trim(maxAge),
          detail: '预检结果可被浏览器缓存 ' + ageDetail + '。'
        });
      }
    }

    if (originInfo.ok) {
      var vh = varyHint(response, acao);
      if (vh) add('vary', vh);
    }

    var expose = exposedHeaders(response, credentialed);
    if (mode === 'actual' || !classified.preflightNeeded) {
      checks.push({
        id: 'expose',
        ok: true,
        level: expose.hidden.length ? 'info' : 'pass',
        title: expose.hidden.length
          ? '部分响应头对前端不可见'
          : '可见响应头都在安全列表或已 Expose',
        detail: (expose.readable.length ? '可读：' + expose.readable.join(', ') + '。' : '没有普通响应头。') +
          (expose.hidden.length ? ' 不可读（需写入 Access-Control-Expose-Headers）：' + expose.hidden.join(', ') + '。' : '')
      });
    }

    if (mode === 'actual' && classified.preflightNeeded) {
      checks.push({
        id: 'missing-preflight',
        ok: false,
        level: 'fail',
        title: '这份响应不像预检结果，但浏览器会先发 OPTIONS',
        detail: '非简单请求会先预检。请改贴 OPTIONS 预检的响应（需 2xx，并带 Allow-Methods / Allow-Headers），或把「检查对象」切到「预检响应」后补全这些头。实际响应即使带了 Allow-Origin，预检失败整个请求也不会发出。'
      });
    }

    if (headerValue(response, 'access-control-allow-private-network') ||
        reqHeaders.some(function (h) { return h.name.toLowerCase() === 'access-control-request-private-network'; })) {
      var pna = headerValue(response, 'access-control-allow-private-network');
      var pnaOk = pna && trim(pna).toLowerCase() === 'true';
      checks.push({
        id: 'pna',
        ok: pnaOk,
        level: pnaOk ? 'pass' : 'fail',
        title: pnaOk ? '已允许 Private Network Access' : '公网页访问私网/本机时还需要 Private-Network 头',
        detail: pnaOk
          ? '响应含 Access-Control-Allow-Private-Network: true。'
          : '请求带了 Access-Control-Request-Private-Network，预检响应需要 Access-Control-Allow-Private-Network: true。该机制在不同浏览器中的支持与默认策略仍在变化。'
      });
    }

    var failed = checks.filter(function (c) { return !c.ok; });
    var verdict = failed.length ? 'block' : 'allow';
    var summary;
    if (!originInfo.ok) {
      summary = '无法判断：' + originInfo.error + '。';
    } else if (verdict === 'allow') {
      summary = mode === 'preflight'
        ? '预检预计会通过，浏览器可以接着发出实际请求。实际响应仍需正确的 Allow-Origin（以及携带凭证时的 Allow-Credentials）。'
        : '按这份请求和响应，浏览器预计会放行跨源读取。';
    } else {
      summary = '浏览器预计会拦截。主要原因：' + failed[0].title + '。';
    }

    var suggestedFixes = [];
    failed.forEach(function (c) {
      if (c.id === 'acao' && credentialed) {
        suggestedFixes.push('把 Access-Control-Allow-Origin 改成精确回显 ' + (originInfo.ok ? originInfo.value : '请求的 Origin') + '，不要用 *。');
      } else if (c.id === 'acao') {
        suggestedFixes.push('响应加上 Access-Control-Allow-Origin: ' + (originInfo.ok ? originInfo.value : '* 或精确 Origin') + '（或在不带凭证时用 *）。');
      } else if (c.id === 'acac') {
        suggestedFixes.push('携带凭证时追加 Access-Control-Allow-Credentials: true，且 Allow-Origin 必须是精确源。');
      } else if (c.id === 'methods') {
        suggestedFixes.push('在 Access-Control-Allow-Methods 中显式加入 ' + requestedMethod + '（预检自身也常需要允许 OPTIONS）。');
      } else if (c.id === 'headers') {
        suggestedFixes.push('在 Access-Control-Allow-Headers 中列出要放行的请求头；若使用 Authorization，必须把这个名字写出来，不能只靠 *。');
      } else if (c.id === 'status') {
        suggestedFixes.push('让 OPTIONS 预检走专门路由并返回 204 或 200，不要落到 404/405。');
      } else if (c.id === 'missing-preflight') {
        suggestedFixes.push('先处理 OPTIONS 预检：2xx + Allow-Origin + Allow-Methods + 所需的 Allow-Headers。');
      } else if (c.id === 'pna') {
        suggestedFixes.push('若确实要让公网页访问本机或内网服务，在预检响应中返回 Access-Control-Allow-Private-Network: true。先确认安全风险。');
      }
    });
    // unique
    var seenFix = {};
    suggestedFixes = suggestedFixes.filter(function (f) {
      if (seenFix[f]) return false;
      seenFix[f] = true;
      return true;
    });

    return {
      origin: originInfo,
      method: methodUpper,
      credentialed: credentialed,
      classification: classified,
      mode: mode,
      requestedMethod: requestedMethod,
      response: response,
      verdict: verdict,
      summary: summary,
      checks: checks,
      readableHeaders: expose.readable,
      hiddenHeaders: expose.hidden,
      suggestedFixes: suggestedFixes,
      maxAge: maxAge
    };
  }

  function toMarkdown(result) {
    var lines = [];
    lines.push('# CORS 检查结果');
    lines.push('');
    lines.push('- 结论：' + (result.verdict === 'allow' ? '预计放行' : '预计拦截'));
    lines.push('- Origin：' + (result.origin && result.origin.value ? result.origin.value : '（无效）'));
    lines.push('- 方法：' + result.method);
    lines.push('- 携带凭证：' + (result.credentialed ? '是' : '否'));
    lines.push('- 检查对象：' + (result.mode === 'preflight' ? '预检响应' : '实际响应'));
    lines.push('- 简单请求：' + (result.classification && result.classification.simple ? '是' : '否'));
    lines.push('');
    lines.push(result.summary);
    lines.push('');
    lines.push('## 检查项');
    (result.checks || []).forEach(function (c) {
      var mark = c.level === 'pass' ? '通过' : c.level === 'fail' ? '失败' : c.level === 'warn' ? '注意' : '说明';
      lines.push('- **' + mark + '** ' + c.title + (c.detail ? ' — ' + c.detail : ''));
    });
    if (result.suggestedFixes && result.suggestedFixes.length) {
      lines.push('');
      lines.push('## 可尝试的改法');
      result.suggestedFixes.forEach(function (f) {
        lines.push('- ' + f);
      });
    }
    lines.push('');
    lines.push('由 cors-lab 在本地生成，未上传任何请求。');
    return lines.join('\n');
  }

  var SAMPLES = {
    simpleOk: {
      label: '简单 GET 放行',
      origin: 'https://app.example.com',
      method: 'GET',
      credentialed: false,
      requestHeadersText: 'Accept: application/json',
      responseText: [
        'HTTP/1.1 200 OK',
        'Access-Control-Allow-Origin: *',
        'Content-Type: application/json',
        'Cache-Control: max-age=60'
      ].join('\n')
    },
    jsonPreflightOk: {
      label: 'JSON POST 预检通过',
      origin: 'https://app.example.com',
      method: 'OPTIONS',
      credentialed: false,
      requestHeadersText: [
        'Access-Control-Request-Method: POST',
        'Access-Control-Request-Headers: content-type'
      ].join('\n'),
      responseText: [
        'HTTP/1.1 204 No Content',
        'Access-Control-Allow-Origin: https://app.example.com',
        'Access-Control-Allow-Methods: GET, POST, OPTIONS',
        'Access-Control-Allow-Headers: Content-Type',
        'Access-Control-Max-Age: 7200',
        'Vary: Origin'
      ].join('\n')
    },
    credStar: {
      label: '凭证 + 通配符（会被拦）',
      origin: 'https://app.example.com',
      method: 'GET',
      credentialed: true,
      requestHeadersText: 'Accept: application/json',
      responseText: [
        'HTTP/1.1 200 OK',
        'Access-Control-Allow-Origin: *',
        'Access-Control-Allow-Credentials: true',
        'Content-Type: application/json'
      ].join('\n')
    },
    originMismatch: {
      label: 'Origin 不匹配',
      origin: 'https://app.example.com',
      method: 'GET',
      credentialed: false,
      requestHeadersText: '',
      responseText: [
        'HTTP/1.1 200 OK',
        'Access-Control-Allow-Origin: https://admin.example.com',
        'Content-Type: text/plain'
      ].join('\n')
    },
    authStar: {
      label: 'Authorization 只写了 *',
      origin: 'https://app.example.com',
      method: 'OPTIONS',
      credentialed: false,
      requestHeadersText: [
        'Access-Control-Request-Method: GET',
        'Access-Control-Request-Headers: authorization'
      ].join('\n'),
      responseText: [
        'HTTP/1.1 204 No Content',
        'Access-Control-Allow-Origin: https://app.example.com',
        'Access-Control-Allow-Methods: GET, OPTIONS',
        'Access-Control-Allow-Headers: *'
      ].join('\n')
    },
    fileNull: {
      label: '本地 file://（Origin: null）',
      origin: 'null',
      method: 'GET',
      credentialed: false,
      requestHeadersText: '',
      responseText: [
        'HTTP/1.1 200 OK',
        'Access-Control-Allow-Origin: *',
        'Content-Type: application/json'
      ].join('\n')
    }
  };

  return {
    parseHeaders: parseHeaders,
    parseRequestHeaders: parseRequestHeaders,
    classifyRequest: classifyRequest,
    analyze: analyze,
    toMarkdown: toMarkdown,
    originKind: originKind,
    samples: SAMPLES
  };
});
