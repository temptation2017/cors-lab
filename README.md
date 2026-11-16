# cors-lab

把跨源请求的 `Origin`、方法、请求头和响应里的 CORS 头贴进来，在浏览器里本地判断：这次请求会不会被放行、要不要先发 OPTIONS 预检、卡在哪一条规则上。**纯前端，不上传。**

在线试用：<https://temptation2017.github.io/cors-lab/>

## 做什么

- 区分简单请求和需要预检的请求（非 GET/HEAD/POST、`Content-Type: application/json`、自定义头、`Authorization` 等）
- 检查 `Access-Control-Allow-Origin` 是否与 Origin 一致，包括 `*`、`null`、多源误写、末尾斜杠
- 携带凭证（Cookie / `withCredentials` / `credentials: "include"`）时，拒绝 `*`，并要求字面量 `Access-Control-Allow-Credentials: true`
- 预检：状态码须为 2xx，核对 `Allow-Methods` / `Allow-Headers`；`*` 在携带凭证时无效
- `Authorization` 必须被显式写出，`Allow-Headers: *` 覆盖不了它
- 列出前端能读到的响应头，以及需要写入 `Access-Control-Expose-Headers` 才能读的头
- 按 Origin 回显时，提醒补上 `Vary: Origin`
- 识别 Private Network Access 预检头（公网页访问本机/内网时）
- 一键复制 Markdown 摘要

全部在本机计算，不会把粘贴内容发到任何服务器，也不向目标站点发真实请求。

## 怎么打开

- 打开 GitHub Pages：<https://temptation2017.github.io/cors-lab/>
- 或本地下载后双击 `index.html`，或：

```bash
python3 -m http.server 8080
# 浏览器访问 http://127.0.0.1:8080/
```

无需构建、无需 npm。

可选校验（零依赖，只需 Node.js）：

```bash
node test_cors.js
```

## 怎么用

1. 填写请求的 `Origin` 和方法。若前端开了 `withCredentials` 或会带 Cookie，勾选「携带凭证」。
2. 需要时粘贴请求头。预检场景可写 `Access-Control-Request-Method` 和 `Access-Control-Request-Headers`。
3. 在右侧粘贴响应头（可带 `HTTP/1.1 204 No Content` 这样的状态行）。
4. 页面会立刻给出「预计放行 / 预计拦截」和逐项说明。「检查对象」默认为自动判断：看起来像 OPTIONS 预检就按预检检查，否则按实际响应检查。
5. 用示例按钮对比常见踩坑：凭证配 `*`、Origin 写错、`Authorization` 只写了 `*`、本地 `file://` 的 `Origin: null`。
6. 要把结论带走，点「复制 Markdown 摘要」。

## 示例

下列域名和令牌都是虚构样本，规则与 [Fetch 的 CORS 协议](https://fetch.spec.whatwg.org/#http-cors-protocol) 在常见浏览器中的行为一致。

| 场景 | 结果 | 原因要点 |
| --- | --- | --- |
| `GET` + `Allow-Origin: *`，不带凭证 | 放行 | 简单请求，`*` 可用 |
| `OPTIONS` 预检，`POST` + `Content-Type: application/json`，2xx 且方法/头都放行 | 放行 | 非简单请求先预检 |
| `GET` 携带凭证 + `Allow-Origin: *` | 拦截 | 带 Cookie 时必须精确回显 Origin |
| `Allow-Origin` 写成另一个子域 | 拦截 | 必须与请求 Origin 字节级一致 |
| 预检要放行 `Authorization`，但只写了 `Allow-Headers: *` | 拦截 | `*` 覆盖不了 `Authorization` |
| `Origin: null`（如本地 `file://` 打开的页面）+ `Allow-Origin: *` | 放行（有提示） | 规范上可过，但放行 `null` 通常不建议 |

## 限制与可改进点

- 这是规则说明器，不会向目标 URL 发真实请求，也不读取浏览器的实际 CORS 实现差异（例如预检缓存上限、重定向后再跨源、部分旧浏览器对 `*` 的处理）。
- 不解析完整的 HTTP 报文实体，只看头。也不模拟 Service Worker、opaque 响应或 `no-cors` 模式。
- 简单请求的判断按现行 Fetch 安全列表；`Range` 只把 `bytes=数字-` 这种单边范围视为安全列表头。
- `Access-Control-Allow-Credentials` 只接受小写字面量 `true`。
- Private Network Access 仍在演进，这里只做头是否齐全的提示。
- 可改进：对照一份 nginx / Spring 配置生成建议头、把失败项画成请求时序、支持同时贴「预检响应 + 实际响应」并排看。
- `test_cors.js` 覆盖了常见放行/拦截用例（可选，零依赖）。

## License

MIT
