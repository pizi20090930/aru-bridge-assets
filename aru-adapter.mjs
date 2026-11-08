#!/usr/bin/env node
// 心潮念 → Aru 适配器 v1.1（2026-11-02）· 作者 White-ting · 构建 fc88
// 原版只从作者那里拿。使用权限见 LICENSE；其中「加密投递」一段照 aru-host 的 wake-send.mjs（Apache-2.0）改写，见 LICENSE-APACHE。
//
// 它是心潮念官方 Runtime Bridge 的一个「进程 Adapter」：桥每收到一条投递，就启动一次本文件，
// 把一行 JSON 信封写进 stdin；本文件把内容加密后投给你的 Aru Host（Aru 的「外部触发」），
// Host 收下就退出码 0（桥回传 delivered），没收下就非零、在 stderr 留一句不含正文的原因。
//
// 只用 Node 20+ 自带的东西，不用 npm install。
//
// 三种用法：
//   node aru-adapter.mjs                 给桥用（从 stdin 读信封）
//   node aru-adapter.mjs check           只检查发送凭证文件写得对不对，不发东西
//   node aru-adapter.mjs test "一句话"    往 Aru 发一条测试，看 Aru 收不收得到
//
// 环境变量：
//   ARU_BUNDLE_FILE               Aru 导出的发送凭证（sender bundle）存成的文件，写绝对路径（必填）
//   XINCHAO_ADAPTER_CABIN_NAME    她发起的消息的前缀名，默认 小屋桥（跟官方示例一样）
//   XINCHAO_ADAPTER_STATE_DIR     记"哪些已经投过"的目录，默认 ~/.xinchao-adapter-aru
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const VERSION = "1.1", RELEASED = "2026-11-02", BUILD = "fc88";   // BUILD 是构建号，打包时按拿到的人换掉
const BUNDLE_FILE = String(process.env.ARU_BUNDLE_FILE ?? "").trim();
const CABIN = String(process.env.XINCHAO_ADAPTER_CABIN_NAME ?? "小屋桥").trim() || "小屋桥";
const STATE_DIR = String(process.env.XINCHAO_ADAPTER_STATE_DIR ?? join(homedir(), ".xinchao-adapter-aru")).trim();
const SEEN_FILE = join(STATE_DIR, "delivered.json");
const MAX_TEXT = 4000;

function fail(msg, code = 1) { process.stderr.write(`${msg}\n`); process.exit(code); }

// ---------- 渲染：照心潮念官方 examples/render.mjs，前面加一行说明来源 ----------
const REASON_LABEL = { user_interaction: "互动", user_note: "留话", scheduled_interaction: "预约", user_feedback: "反馈" };
function renderText(env) {
  const message = String(env.message ?? "").trim();
  if (env.reason === "self_signal") return `【心潮】${message}`;
  const label = REASON_LABEL[env.reason] || "消息";
  return `【${CABIN}·${label}】${message.replace(/\s+/g, " ")}（${CABIN}递的，心里有数就行，不用特意回。）`;
}
function forAru(env) {
  const head = env.reason === "self_signal"
    ? "〔心潮念 · 动态桥〕这是你自己在心潮里浮上来的感觉，不是她发的消息。要不要去找她、说什么，你自己定；也可以什么都不说。"
    : "〔心潮念 · 动态桥〕这是她在心潮小屋里做的事，经心潮递过来的，不是她在 Aru 里发的消息。";
  return (head + "\n" + renderText(env)).slice(0, MAX_TEXT);
}

// ---------- 加密投递：照 aru-host 的 wake-send.mjs（Apache-2.0）用 WebCrypto 改写 ----------
// 发送凭证：{schema, triggerId, submitURL, submitToken, encryptionKey(base64, 32 字节)}
const b64ToBytes = (s) => Uint8Array.from(Buffer.from(String(s), "base64"));
const bytesToB64 = (u8) => Buffer.from(u8).toString("base64");

function loadBundle() {
  if (!BUNDLE_FILE) fail("没设 ARU_BUNDLE_FILE（发送凭证文件的路径）");
  if (!existsSync(BUNDLE_FILE)) fail("找不到发送凭证文件，看看 ARU_BUNDLE_FILE 的路径对不对");
  let b;
  try { b = JSON.parse(readFileSync(BUNDLE_FILE, "utf8").replace(/^/, "")); } catch { fail("发送凭证文件不是完整的 JSON：从 Aru 里重新复制一次，整段粘进去"); }
  if (b?.schema !== "aru.wake-bridge.sender-bundle.v2") fail("发送凭证的版本不对：要 Aru 导出的 sender bundle v2");
  if (typeof b.triggerId !== "string" || !b.triggerId) fail("发送凭证里缺 triggerId");
  const httpOk = process.env.ARU_ADAPTER_TEST_ALLOW_HTTP === "1";   // 只给本机测试用
  if (typeof b.submitURL !== "string" || !(httpOk ? /^https?:\/\// : /^https:\/\//).test(b.submitURL)) fail("发送凭证里的 submitURL 要是 https 开头（Host 要有公网 HTTPS 地址）");
  if (typeof b.submitToken !== "string" || !b.submitToken) fail("发送凭证里缺 submitToken");
  if (b64ToBytes(b.encryptionKey || "").length !== 32) fail("发送凭证里的密钥不是 32 字节");
  return b;
}

async function seal(bundle, text, eventId) {
  const payload = new TextEncoder().encode(JSON.stringify({ schema: "aru.wake-bridge.payload.v2", eventId, triggerId: bundle.triggerId, content: text }));
  const key = await crypto.subtle.importKey("raw", b64ToBytes(bundle.encryptionKey), "AES-GCM", false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, payload));   // 密文 || 16 字节标签
  const sealed = new Uint8Array(nonce.length + ct.length);
  sealed.set(nonce, 0);
  sealed.set(ct, nonce.length);
  return { schema: "aru.wake-bridge.sealed-event.v1", eventId, sealedPayload: bytesToB64(sealed) };
}

async function submit(bundle, text, eventId) {
  const body = JSON.stringify(await seal(bundle, text, eventId));
  let r;
  try {
    r = await fetch(bundle.submitURL, {
      method: "POST",
      headers: { authorization: `Bearer ${bundle.submitToken}`, "content-type": "application/json", "user-agent": `xinchao-aru-adapter/${VERSION} (White-ting; ${BUILD})` },
      body, redirect: "manual", signal: AbortSignal.timeout(20000),
    });
  } catch (e) {
    fail(`连不上 Aru Host：${e?.cause?.code || e?.name || "网络出错"}（Host 开着吗？公网地址通吗？）`);
  }
  if (r.status >= 300 && r.status < 400) fail(`Aru Host 的地址被重定向了（HTTP ${r.status}），不投`);
  if (r.status === 401 || r.status === 403) fail(`Aru Host 不认这份发送凭证（HTTP ${r.status}）：触发器可能删了或重建过，重新导出一份`);
  if (r.status === 404) fail("Aru Host 上没有这个触发器（HTTP 404）：重新导出发送凭证");
  if (!r.ok) fail(`Aru Host 没收下（HTTP ${r.status}）`);
}

// 同一条投递每次用同一个事件编号（由 deliveryId 算出来、长得像 UUID），Host 那边也能认出重复
async function eventIdFor(deliveryId) {
  const h = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("xinchao-aru:" + deliveryId))).toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-${((parseInt(h[16], 16) & 3) | 8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

// ---------- 幂等：同一个 deliveryId 只投一次（投过但回执丢了，桥会再来一次） ----------
function seen() { try { return new Set(JSON.parse(readFileSync(SEEN_FILE, "utf8"))); } catch { return new Set(); } }
function remember(set, id) {
  mkdirSync(STATE_DIR, { recursive: true });
  writeFileSync(SEEN_FILE, JSON.stringify([...set, id].slice(-2000)));
}

const [cmd, arg] = process.argv.slice(2);
if (cmd === "check") {
  const b = loadBundle();
  console.log(`心潮念 → Aru 适配器 v${VERSION}（${RELEASED}）· White-ting · 构建 ${BUILD}`);
  console.log(`发送凭证没问题：触发器 …${b.triggerId.slice(-6)}，投到 ${new URL(b.submitURL).host}`);
  process.exit(0);
}
if (cmd === "test") {
  const b = loadBundle();
  const text = "〔心潮念 · 动态桥 · 测试〕这是一条测试，用来确认心潮念能把消息递到 Aru。看到了就说明接通了，不用当真。" + (arg ? "\n" + arg : "");
  await submit(b, text, crypto.randomUUID());
  console.log("Aru Host 收下了。去 Aru 里看那位协作者有没有动静。");
  process.exit(0);
}
if (cmd) fail("不认识的用法：只有 check、test，或者不带参数给桥用");

// 给桥用
let env;
try { env = JSON.parse(readFileSync(0, "utf8").trim()); } catch { fail("信封不是 JSON"); }
if (env?.protocol !== "xinchao-runtime-wake/1") fail("信封协议不认识");
if (typeof env.deliveryId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{5,159}$/.test(env.deliveryId)) fail("信封缺 deliveryId");
if (typeof env.reason !== "string" || typeof env.message !== "string" || !env.message.trim()) fail("信封缺内容");
const done = seen();
if (done.has(env.deliveryId)) process.exit(0);   // 投过了，只是回执丢了
const bundle = loadBundle();
await submit(bundle, forAru(env), await eventIdFor(env.deliveryId));
remember(done, env.deliveryId);
process.exit(0);
