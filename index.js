import { connect } from "cloudflare:sockets";

// Global configuration including the authentication token, default destination URL, and debug mode flag
const CONFIG = {
  AUTH_TOKEN: "你的认证路径",
  DEFAULT_DST_URL: "https://example.com/",
  DEBUG_MODE: false,
  // 新增验证码密码配置，客户端提交正确密码后会在 Cookie 中写入该密码
  PASSWORD: "认证路径上的密码",
  // 新增安全路径配置，当请求路径第一个分段为 SafePath 时不需要 Cookie 验证
  SafePath: "安全路径，此路径无需密码验证",
};

// Update global configuration from environment variables (prioritizing environment values)
function updateConfigFromEnv(env) {
  if (!env) return;
  for (const key of Object.keys(CONFIG)) {
    if (key in env) {
      if (typeof CONFIG[key] === "boolean") {
        CONFIG[key] = env[key] === "true";
      } else {
        CONFIG[key] = env[key];
      }
    }
  }
}

// Define text encoder and decoder for converting between strings and byte arrays
const encoder = new TextEncoder();
const decoder = new TextDecoder();

// Filter out HTTP headers that should not be forwarded (ignore headers: host, accept-encoding, cf-*)
const HEADER_FILTER_RE = /^(host|accept-encoding|cf-)/i;

// Define the debug log output function based on the debug mode setting
const log = CONFIG.DEBUG_MODE
  ? (message, data = "") => console.log(`[DEBUG] ${message}`, data)
  : () => {};

// Concatenate multiple Uint8Arrays into a single new Uint8Array
function concatUint8Arrays(...arrays) {
  const total = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

// Parse HTTP response headers, returning the status code, status text, headers, and the header section's end position
function parseHttpHeaders(buff) {
  const text = decoder.decode(buff);
  // Look for the end of HTTP headers indicated by "\r\n\r\n"
  const headerEnd = text.indexOf("\r\n\r\n");
  if (headerEnd === -1) return null;
  const headerSection = text.slice(0, headerEnd).split("\r\n");
  const statusLine = headerSection[0];
  // Match the HTTP status line, e.g., "HTTP/1.1 200 OK"
  const statusMatch = statusLine.match(/HTTP\/1\.[01] (\d+) (.*)/);
  if (!statusMatch) throw new Error(`Invalid status line: ${statusLine}`);
  const headers = new Headers();
  // Parse the response headers
  for (let i = 1; i < headerSection.length; i++) {
    const line = headerSection[i];
    const idx = line.indexOf(": ");
    if (idx !== -1) {
      headers.append(line.slice(0, idx), line.slice(idx + 2));
    }
  }
  return { status: Number(statusMatch[1]), statusText: statusMatch[2], headers, headerEnd };
}

// Read data from the reader until a double CRLF (indicating the end of HTTP headers) is encountered
async function readUntilDoubleCRLF(reader) {
  let respText = "";
  while (true) {
    const { value, done } = await reader.read();
    if (value) {
      respText += decoder.decode(value, { stream: true });
      if (respText.includes("\r\n\r\n")) break;
    }
    if (done) break;
  }
  return respText;
}

// Async generator: read chunked HTTP response data chunks and yield each chunk sequentially
async function* readChunks(reader, buff = new Uint8Array()) {
  while (true) {
    // Look for the position of the CRLF separator in the existing buffer
    let pos = -1;
    for (let i = 0; i < buff.length - 1; i++) {
      if (buff[i] === 13 && buff[i + 1] === 10) {
        pos = i;
        break;
      }
    }
    // If not found, continue reading more data to fill the buffer
    if (pos === -1) {
      const { value, done } = await reader.read();
      if (done) break;
      buff = concatUint8Arrays(buff, value);
      continue;
    }
    // Parse the chunk size (in hexadecimal format)
    const size = parseInt(decoder.decode(buff.slice(0, pos)), 16);
    log("Read chunk size", size);
    // A size of 0 indicates the end of chunks
    if (!size) break;
    // Remove the parsed size part and the following CRLF from the buffer
    buff = buff.slice(pos + 2);
    // Ensure the buffer contains the complete chunk (including the trailing CRLF)
    while (buff.length < size + 2) {
      const { value, done } = await reader.read();
      if (done) throw new Error("Unexpected EOF in chunked encoding");
      buff = concatUint8Arrays(buff, value);
    }
    // Yield the chunk data (excluding the trailing CRLF)
    yield buff.slice(0, size);
    buff = buff.slice(size + 2);
  }
}

// Parse the complete HTTP response, handling the response body data based on transfer mode (chunked or fixed-length)
async function parseResponse(reader) {
  let buff = new Uint8Array();
  while (true) {
    const { value, done } = await reader.read();
    if (value) {
      buff = concatUint8Arrays(buff, value);
      const parsed = parseHttpHeaders(buff);
      if (parsed) {
        const { status, statusText, headers, headerEnd } = parsed;
        const isChunked = headers.get("transfer-encoding")?.includes("chunked");
        const contentLength = parseInt(headers.get("content-length") || "0", 10);
        const data = buff.slice(headerEnd + 4);
        // Distribute the response body data via a ReadableStream
        return new Response(
          new ReadableStream({
            async start(ctrl) {
              try {
                if (isChunked) {
                  log("Using chunked transfer mode");
                  // Chunked transfer mode: read and enqueue each chunk sequentially
                  for await (const chunk of readChunks(reader, data)) {
                    ctrl.enqueue(chunk);
                  }
                } else {
                  log("Using fixed-length transfer mode", { contentLength });
                  let received = data.length;
                  if (data.length) ctrl.enqueue(data);
                  // Fixed-length mode: read the specified number of bytes based on content-length
                  while (received < contentLength) {
                    const { value, done } = await reader.read();
                    if (done) break;
                    received += value.length;
                    ctrl.enqueue(value);
                  }
                }
                ctrl.close();
              } catch (err) {
                log("Error parsing response", err);
                ctrl.error(err);
              }
            },
          }),
          { status, statusText, headers }
        );
      }
    }
    if (done) break;
  }
  throw new Error("Unable to parse response headers");
}

// Generate a random Sec-WebSocket-Key required for the WebSocket handshake
function generateWebSocketKey() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

// Pack a text message into a WebSocket frame (currently supports only text frames with payloads not too large)
function packTextFrame(payload) {
  const FIN_AND_OP = 0x81; // FIN flag and text frame opcode
  const maskBit = 0x80; // Mask bit (must be set to 1 for client-sent messages)
  const len = payload.length;
  let header;
  if (len < 126) {
    header = new Uint8Array(2);
    header[0] = FIN_AND_OP;
    header[1] = maskBit | len;
  } else if (len < 65536) {
    header = new Uint8Array(4);
    header[0] = FIN_AND_OP;
    header[1] = maskBit | 126;
    header[2] = (len >> 8) & 0xff;
    header[3] = len & 0xff;
  } else {
    throw new Error("Payload too large");
  }
  // Generate a 4-byte random mask
  const mask = new Uint8Array(4);
  crypto.getRandomValues(mask);
  const maskedPayload = new Uint8Array(len);
  // Apply the mask to the payload
  for (let i = 0; i < len; i++) {
    maskedPayload[i] = payload[i] ^ mask[i % 4];
  }
  // Concatenate the frame header, mask, and masked payload
  return concatUint8Arrays(header, mask, maskedPayload);
}

// Class for parsing and reassembling WebSocket frames, supporting fragmented messages
class SocketFramesReader {
  constructor(reader) {
    this.reader = reader;
    this.buffer = new Uint8Array();
    this.fragmentedPayload = null;
    this.fragmentedOpcode = null;
  }
  // Ensure that the buffer has enough bytes for parsing
  async ensureBuffer(length) {
    while (this.buffer.length < length) {
      const { value, done } = await this.reader.read();
      if (done) return false;
      this.buffer = concatUint8Arrays(this.buffer, value);
    }
    return true;
  }
  // Parse the next WebSocket frame and handle fragmentation (opcode 0 indicates continuation)
  async nextFrame() {
    while (true) {
      if (!(await this.ensureBuffer(2))) return null;
      const first = this.buffer[0],
        second = this.buffer[1],
        fin = (first >> 7) & 1,
        opcode = first & 0x0f,
        isMasked = (second >> 7) & 1;
      let payloadLen = second & 0x7f,
        offset = 2;
      // If payload length is 126, parse the next two bytes for the actual length
      if (payloadLen === 126) {
        if (!(await this.ensureBuffer(offset + 2))) return null;
        payloadLen = (this.buffer[offset] << 8) | this.buffer[offset + 1];
        offset += 2;
      } else if (payloadLen === 127) {
        throw new Error("127 length mode is not supported");
      }
      let mask;
      if (isMasked) {
        if (!(await this.ensureBuffer(offset + 4))) return null;
        mask = this.buffer.slice(offset, offset + 4);
        offset += 4;
      }
      if (!(await this.ensureBuffer(offset + payloadLen))) return null;
      let payload = this.buffer.slice(offset, offset + payloadLen);
      if (isMasked && mask) {
        for (let i = 0; i < payload.length; i++) {
          payload[i] ^= mask[i % 4];
        }
      }
      // Remove the processed bytes from the buffer
      this.buffer = this.buffer.slice(offset + payloadLen);
      // Opcode 0 indicates a continuation frame: concatenate the fragmented data
      if (opcode === 0) {
        if (this.fragmentedPayload === null)
          throw new Error("Received continuation frame without initiation");
        this.fragmentedPayload = concatUint8Arrays(this.fragmentedPayload, payload);
        if (fin) {
          const completePayload = this.fragmentedPayload;
          const completeOpcode = this.fragmentedOpcode;
          this.fragmentedPayload = this.fragmentedOpcode = null;
          return { fin: true, opcode: completeOpcode, payload: completePayload };
        }
      } else {
        // If there is fragmented data but the current frame is not a continuation, reset the fragmentation state
        if (!fin) {
          this.fragmentedPayload = payload;
          this.fragmentedOpcode = opcode;
          continue;
        } else {
          if (this.fragmentedPayload) {
            this.fragmentedPayload = this.fragmentedOpcode = null;
          }
          return { fin, opcode, payload };
        }
      }
    }
  }
}

// Forward HTTP requests or WebSocket handshake and data based on the request type
async function nativeFetch(req, dstUrl) {
  // Clean up the headers by removing those that match the filter criteria
  const cleanedHeaders = new Headers();
  for (const [k, v] of req.headers) {
    if (!HEADER_FILTER_RE.test(k)) {
      cleanedHeaders.set(k, v);
    }
  }
  
  // Check if the request is a WebSocket request
  const upgradeHeader = req.headers.get("Upgrade")?.toLowerCase();
  const isWebSocket = upgradeHeader === "websocket";
  const targetUrl = new URL(dstUrl);
  
  if (isWebSocket) {
    // If the target URL does not support the WebSocket protocol, return an error response
    if (!/^wss?:\/\//i.test(dstUrl)) {
      return new Response("Target does not support WebSocket", { status: 400 });
    }
    const isSecure = targetUrl.protocol === "wss:";
    const port = targetUrl.port || (isSecure ? 443 : 80);
    // Establish a raw socket connection to the target server
    const socket = await connect(
      { hostname: targetUrl.hostname, port: Number(port) },
      { secureTransport: isSecure ? "on" : "off" }
    );
  
    // Generate the key required for the WebSocket handshake
    const key = generateWebSocketKey();

    // Construct the HTTP headers required for the handshake
    cleanedHeaders.set("Host", targetUrl.hostname);
    cleanedHeaders.set("Connection", "Upgrade");
    cleanedHeaders.set("Upgrade", "websocket");
    cleanedHeaders.set("Sec-WebSocket-Version", "13");
    cleanedHeaders.set("Sec-WebSocket-Key", key);
  
    // Assemble the HTTP request data for the WebSocket handshake
    const handshakeReq =
      `GET ${targetUrl.pathname}${targetUrl.search} HTTP/1.1\r\n` +
      Array.from(cleanedHeaders.entries())
        .map(([k, v]) => `${k}: ${v}`)
        .join("\r\n") +
      "\r\n\r\n";

    log("Sending WebSocket handshake request", handshakeReq);
    const writer = socket.writable.getWriter();
    await writer.write(encoder.encode(handshakeReq));
  
    const reader = socket.readable.getReader();
    const handshakeResp = await readUntilDoubleCRLF(reader);
    log("Received handshake response", handshakeResp);
    // Verify that the handshake response indicates a 101 Switching Protocols status
    if (
      !handshakeResp.includes("101") ||
      !handshakeResp.includes("Switching Protocols")
    ) {
      throw new Error("WebSocket handshake failed: " + handshakeResp);
    }
  
    // Create an internal WebSocketPair
    const [client, server] = new WebSocketPair();
    client.accept();
    // Establish bidirectional frame relaying between the client and the remote socket
    relayWebSocketFrames(client, socket, writer, reader);
    return new Response(null, { status: 101, webSocket: server });
  } else {
    // For standard HTTP requests: set required headers (such as Host and disable compression)
    cleanedHeaders.set("Host", targetUrl.hostname);
    cleanedHeaders.set("accept-encoding", "identity");
  
    const port = targetUrl.protocol === "https:" ? 443 : 80;
    const socket = await connect(
      { hostname: targetUrl.hostname, port },
      { secureTransport: targetUrl.protocol === "https:" ? "on" : "off" }
    );
    const writer = socket.writable.getWriter();
    // Construct the request line and headers
    const requestLine =
      `${req.method} ${targetUrl.pathname}${targetUrl.search} HTTP/1.1\r\n` +
      Array.from(cleanedHeaders.entries())
        .map(([k, v]) => `${k}: ${v}`)
        .join("\r\n") +
      "\r\n\r\n";
    log("Sending request", requestLine);
    await writer.write(encoder.encode(requestLine));
  
    // If there is a request body, forward it to the target server
    if (req.body) {
      log("Forwarding request body");
      for await (const chunk of req.body) {
        await writer.write(chunk);
      }
    }
    // Parse and return the target server's response
    return await parseResponse(socket.readable.getReader());
  }
}

// Relay WebSocket frames bidirectionally between the client and the remote socket
function relayWebSocketFrames(ws, socket, writer, reader) {
  // Listen for messages from the client, package them into frames, and send them to the remote socket
  ws.addEventListener("message", async (event) => {
    let payload;
    if (typeof event.data === "string") {
      payload = encoder.encode(event.data);
    } else if (event.data instanceof ArrayBuffer) {
      payload = new Uint8Array(event.data);
    } else {
      payload = event.data;
    }
    const frame = packTextFrame(payload);
    try {
      await writer.write(frame);
    } catch (e) {
      log("Remote write error", e);
    }
  });
  
  // Asynchronously relay WebSocket frames received from the remote to the client
  (async function relayFrames() {
    const frameReader = new SocketFramesReader(reader);
    try {
      while (true) {
        const frame = await frameReader.nextFrame();
        if (!frame) break;
        // Process the data frame based on its opcode
        switch (frame.opcode) {
          case 1: // Text frame
          case 2: // Binary frame
            ws.send(frame.payload);
            break;
          case 8: // Close frame
            log("Received Close frame, closing WebSocket");
            ws.close(1000);
            return;
          default:
            log(`Received unknown frame type, Opcode: ${frame.opcode}`);
        }
      }
    } catch (e) {
      log("Error reading remote frame", e);
    } finally {
      ws.close();
      writer.releaseLock();
      socket.close();
    }
  })();
  
  // When the client WebSocket closes, also close the remote socket connection
  ws.addEventListener("close", () => socket.close());
}

// 解析 Cookie 字符串，返回一个键值对象
function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(";").forEach(cookie => {
    const [name, ...rest] = cookie.split("=");
    cookies[name.trim()] = rest.join("=").trim();
  });
  return cookies;
}

// 从请求中去掉用于验证的 Cookie（auth_pwd），返回一个新的 Request 对象
function removeAuthCookie(req) {
  const newHeaders = new Headers(req.headers);
  const cookieHeader = newHeaders.get("Cookie");
  if (cookieHeader) {
    const cookies = parseCookies(cookieHeader);
    delete cookies["auth_pwd"];
    const newCookie = Object.entries(cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join("; ");
    if (newCookie) {
      newHeaders.set("Cookie", newCookie);
    } else {
      newHeaders.delete("Cookie");
    }
  }
  return new Request(req.url, {
    method: req.method,
    headers: newHeaders,
    body: req.body,
  });
}

// 返回密码验证表单页面 HTML，可传入 error 显示错误信息
function getPasswordFormHTML(error = "") {
  return `
  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
  <style>
  body {
    background-color: #fbfbfb;
    font-family: Arial, sans-serif;
  }
  
  h1 {
    text-align: center;
    color: #444;
  }
  
  .container {
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    height: 100vh;
  }
  
  form {
    background-color: white;
    box-shadow: 0 3px 6px rgba(0, 0, 0, 0.16), 0 3px 6px rgba(0, 0, 0, 0.23);
    padding: 2rem;
    border-radius: 8px;
  }
  
  input {
    display: block;
    width: 100%;
    font-size: 18px;
    padding: 15px;
    border: solid 1px #ccc;
    border-radius: 4px;
    margin: 1rem 0;
  }
  
  button {
    padding: 15px;
    background-color: #0288d1;
    color: white;
    font-size: 18px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    width: 100%;
   }
  
  button:hover {
    background-color: #039BE5;
  }
  </style>
    <meta charset="UTF-8">
    <title>密码验证</title>
  </head>
  <body>
  <h1>请输入密码进行验证</h1>
  ${error ? `<p style="color:red;">${error}</p>` : ""}
  <form method="POST">
    <label>密码: <input type="password" name="password"/></label>
    <button type="submit">提交</button>
  </form>
  </body>
  </html>
  `;
}

// 返回中转跳转页面 HTML，本页面内包含目标网址输入框和“浏览”按钮，提交后将跳转至 /AUTH_TOKEN/<目标网址>
function getRedirectPageHTML() {
  return `
  <html lang="zh-CN">
  <head>
  <style>
  body {
    background-color: #fbfbfb;
    font-family: Arial, sans-serif;
  }
  
  h1 {
    text-align: center;
    color: #444;
  }
  
  .container {
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    height: 100vh;
  }
  
  form {
    background-color: white;
    box-shadow: 0 3px 6px rgba(0, 0, 0, 0.16), 0 3px 6px rgba(0, 0, 0, 0.23);
    padding: 2rem;
    border-radius: 8px;
  }
  
  input {
    display: block;
    width: 100%;
    font-size: 18px;
    padding: 15px;
    border: solid 1px #ccc;
    border-radius: 4px;
    margin: 1rem 0;
  }
  
  button {
    padding: 15px;
    background-color: #0288d1;
    color: white;
    font-size: 18px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    width: 100%;
  }
  
  button:hover {
    background-color: #039BE5;
  }
  </style>
    <meta charset="UTF-8">
    <title>安全访问</title>
  </head>
  <body>
    <h1>请输入安全访问路径</h1>
    <form id="proxy-form">
      <input type="text" id="url" name="url" placeholder="请输入路径" required />
      <button type="submit">安全访问</button>
    </form>
    <script>
      const form = document.getElementById('proxy-form');
      form.addEventListener('submit', event => {
        event.preventDefault();
        const input = document.getElementById('url');
        const actualUrl = input.value;
        const proxyUrl = './' + actualUrl;
        //location.href = proxyUrl;
        window.open(proxyUrl, '_blank');
      });
    </script>
  </body>
  </html>
  `;
}

// Entry point for handling requests: update configuration,判断路径及Cookie后进行相应的密码验证、跳转中转 或 转发请求
async function handleRequest(req, env) {
  updateConfigFromEnv(env);
  CONFIG.DEBUG_MODE = CONFIG.DEBUG_MODE; // 保持debug模式

  const url = new URL(req.url);
  const parts = url.pathname.split("/").filter(Boolean);

  // 如果请求路径的第一个分段是 SafePath，则直接转发（不需要密码验证）
  if (parts[0] === CONFIG.SafePath) {
    let dstUrl;
    if (parts.length >= 2) {
      const [, protocol, ...rest] = parts;
      dstUrl = protocol ? `${protocol}//${rest.join("/")}${url.search}` : CONFIG.DEFAULT_DST_URL;
    } else {
      dstUrl = CONFIG.DEFAULT_DST_URL;
    }
    log("SafePath forwarding", dstUrl);
    return await nativeFetch(req, dstUrl);
  }

  // 如果请求路径的第一个分段是 AUTH_TOKEN，则需要验证密码
  if (parts[0] === CONFIG.AUTH_TOKEN) {
    const cookieHeader = req.headers.get("Cookie");
    const cookies = parseCookies(cookieHeader);
    const validCookie = cookies["auth_pwd"] === CONFIG.PASSWORD;

    // 如果请求方法为 POST，则可能是提交密码或提交目标网址
    if (req.method === "POST") {
      const contentType = req.headers.get("Content-Type") || "";
      if (contentType.includes("application/x-www-form-urlencoded")) {
        const formData = await req.formData();
        // 如果提交了密码字段，则进行密码验证
        if (formData.has("password")) {
          const submittedPassword = formData.get("password").trim();
          if (submittedPassword === CONFIG.PASSWORD) {
            // 密码正确，设置 auth_pwd Cookie，并显示中转跳转页
            return new Response(getRedirectPageHTML(), {
              status: 200,
              headers: {
                "Content-Type": "text/html",
                "Set-Cookie": `auth_pwd=${CONFIG.PASSWORD}; Path=/; HttpOnly`,
              },
            });
          } else {
            // 密码错误，重新显示密码验证表单
            return new Response(getPasswordFormHTML("密码错误，请重试。"), {
              status: 200,
              headers: { "Content-Type": "text/html" },
            });
          }
        } else if (formData.has("destUrl")) {
          // 如果提交了目标网址字段，则跳转到 /AUTH_TOKEN/<destUrl>
          const destUrl = formData.get("destUrl").trim();
          return Response.redirect(`/${CONFIG.AUTH_TOKEN}/${destUrl}`, 302);
        }
      }
    }

    // 如果 Cookie 中没有正确的密码，则显示密码验证表单
    if (!validCookie) {
      return new Response(getPasswordFormHTML(), {
        status: 200,
        headers: { "Content-Type": "text/html" },
      });
    }

    // 当 Cookie 验证正确时：
    // 如果只有 /AUTH_TOKEN（即没有目标网址），则显示跳转中转页供用户输入目标网址
    if (parts.length === 1) {
      return new Response(getRedirectPageHTML(), {
        status: 200,
        headers: { "Content-Type": "text/html" },
      });
    } else {
      // 如果请求路径包含目标地址，则在转发前去掉 auth_pwd Cookie
      const newReq = removeAuthCookie(req);
      // 原先的逻辑： parts 格式为 [AUTH_TOKEN, protocol, ...rest]
      const [, protocol, ...rest] = parts;
      const dstUrl = protocol ? `${protocol}//${rest.join("/")}${url.search}` : CONFIG.DEFAULT_DST_URL;
      log("Forwarding request from /AUTH_TOKEN", dstUrl);
      return await nativeFetch(newReq, dstUrl);
    }
  }

  // 如果请求路径既不属于 SafePath，也不属于 AUTH_TOKEN，则使用原有逻辑（例如转发到默认目标）
  const [auth, protocol, ...rest] = parts;
  const isValid = auth === CONFIG.AUTH_TOKEN;
  const dstUrl = isValid && protocol ? `${protocol}//${rest.join("/")}${url.search}` : CONFIG.DEFAULT_DST_URL;
  log("Fallback forwarding", dstUrl);
  return await nativeFetch(req, dstUrl);
}

// Export the fetch event handler for Cloudflare Workers and related environments
export default { fetch: handleRequest };
export const onRequest = (ctx) => handleRequest(ctx.request, ctx.env);
