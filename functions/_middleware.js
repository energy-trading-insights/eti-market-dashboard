// 公開サイト（market.eti.co.jp・Cloudflare Pages の eti-market-dashboard）のログイン。2026-10-20
//
// すべてのページの手前で動き、ログインしていなければログイン画面へ回す。Cloudflare Access は使えない
// （eti.co.jp の DNS が Cloudflare の外・手元のトークンは Pages の編集だけ）ので、Pages Functions で自前に持つ。
//
// 設定は Pages の環境変数（暗号化した secret）。値はリポジトリに書かない。
//   AUTH_SECRET  … クッキーの署名の鍵（ランダムな文字列）
//   AUTH_USERS   … {"<ID>": {"hash": "pbkdf2_sha256$<回数>$<salt b64>$<hash b64>", "paths": ["/"], "name": "表示名"}}
//                  paths は見てよい範囲（前方一致）。"/" は全ページ、"/quiet-harbor/" はその会社のフォルダだけ
// 設定が無い・壊れているときは**開けない側に倒す**（うっかり公開しない）。
//
// パスワードの照合値は scripts/site_auth.py で作る。ログインの維持は 30 日（署名つきクッキー）。

const COOKIE = "di_auth";
const MAX_AGE = 30 * 24 * 3600;
const LOGIN = "/__login";
const LOGOUT = "/__logout";
const enc = new TextEncoder();

const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64url = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

function sameBytes(a, b) {                       // 時間の差で中身が漏れないよう、最後まで比べる
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(data)));
}

async function verifyPassword(password, stored) {
  const [algo, iter, salt, hash] = String(stored || "").split("$");
  if (algo !== "pbkdf2_sha256" || !iter || !salt || !hash) return false;
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: unb64(salt), iterations: Number(iter) }, key, 256);
  return sameBytes(new Uint8Array(bits), unb64(hash));
}

async function makeToken(secret, user) {
  const body = b64url(enc.encode(JSON.stringify({ u: user, exp: Math.floor(Date.now() / 1000) + MAX_AGE })));
  return body + "." + b64url(await hmac(secret, body));
}

async function readToken(secret, token) {
  const [body, sig] = String(token || "").split(".");
  if (!body || !sig) return null;
  if (!sameBytes(await hmac(secret, body), unb64url(sig))) return null;
  try {
    const p = JSON.parse(new TextDecoder().decode(unb64url(body)));
    return p.exp > Date.now() / 1000 ? p.u : null;
  } catch { return null; }
}

function cookieOf(request) {
  const m = (request.headers.get("Cookie") || "").match(new RegExp("(?:^|;\\s*)" + COOKIE + "=([^;]+)"));
  return m ? m[1] : null;
}

const allowed = (user, path) => (user.paths || []).some((p) => p === "/" || path === p.replace(/\/$/, "") || path.startsWith(p));
// ログイン後の戻り先は、同じサイトの中のパスだけ。ブラウザと同じ解釈で外部への抜け道（//x・/\x など）を塞ぐ
function safeNext(n) {
  try {
    const u = new URL(String(n || "/"), "https://same.invalid");
    if (u.origin !== "https://same.invalid") return "/";
    const p = u.pathname + u.search;
    return p.startsWith(LOGIN) ? "/" : p;
  } catch { return "/"; }
}

function config(env) {
  try {
    const users = JSON.parse(env.AUTH_USERS || "");
    if (!env.AUTH_SECRET || env.AUTH_SECRET.length < 32 || !users || typeof users !== "object") return null;
    return { secret: env.AUTH_SECRET, users };
  } catch { return null; }
}

const HEAD = { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow" };

function page(title, inner, status = 200) {
  return new Response(`<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex, nofollow">
<title>${title}｜データインサイト</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#F6F3EC;color:#2A2620;
 font:15px/1.7 'Zen Kaku Gothic New',"Yu Gothic UI","Meiryo",sans-serif}
.box{width:min(380px,calc(100% - 32px));background:#FBF9F4;border:1px solid #DDD5C4;border-radius:3px;padding:32px 28px}
.logo{font-weight:600;font-size:20px;letter-spacing:.04em}
.ticks{display:flex;gap:1.2px;height:5px;align-items:flex-end;margin:3px 0 22px}
.ticks i{width:1px;height:3px;background:#A89F8C}.ticks i:nth-child(6n+1){height:5px;background:#B68235}
h1{font-family:'Shippori Mincho',"Yu Mincho",serif;font-weight:600;font-size:22px;margin:0 0 6px}
p{margin:0 0 18px;color:#6E665A;font-size:13px}
label{display:block;font-size:13px;color:#4A443A;margin:12px 0 4px}
input{width:100%;box-sizing:border-box;font:inherit;padding:10px 12px;border:1px solid #BDB3A0;border-radius:3px;background:#fff;color:#2A2620}
input:focus{outline:2px solid #B68235;outline-offset:1px}
button{margin-top:20px;width:100%;font:inherit;font-weight:500;padding:12px;border-radius:3px;border:1px solid #B68235;
 background:transparent;color:#7A5413;cursor:pointer}
button:hover{background:#F1E6CE}
.err{color:#C0483A;font-size:13px;margin:10px 0 0}
a{color:#3A7A80}
</style></head><body><main class="box"><div class="logo">データインサイト</div>
<div class="ticks">${"<i></i>".repeat(48)}</div>${inner}</main></body></html>`, { status, headers: HEAD });
}

function loginForm(next, error = "") {
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  return page("ログイン", `<h1>ログイン</h1><p>お渡ししている ID とパスワードを入力してください。</p>
<form method="post" action="${LOGIN}"><input type="hidden" name="next" value="${esc(next)}">
<label for="u">ID</label><input id="u" name="user" autocomplete="username" required autofocus>
<label for="p">パスワード</label><input id="p" name="password" type="password" autocomplete="current-password" required>
${error ? `<div class="err" role="alert">${esc(error)}</div>` : ""}<button type="submit">ログイン</button></form>`, error ? 401 : 200);
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = decodeURIComponent(url.pathname);

  if (path === "/robots.txt") {
    return new Response("User-agent: *\nDisallow: /\n", { headers: { "Content-Type": "text/plain" } });
  }
  const cfg = config(env);
  if (!cfg) {                                      // 設定が無い・壊れている → 開けない側
    return page("準備中", "<h1>準備中です</h1><p>ただいま閲覧できません。しばらくしてからお試しください。</p>", 503);
  }

  if (path === LOGOUT) {
    return new Response(null, { status: 302, headers: { Location: LOGIN, "Set-Cookie": `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax` } });
  }

  if (path === LOGIN) {
    if (request.method === "POST") {
      const form = await request.formData();
      const id = String(form.get("user") || "").trim();
      const nextPath = safeNext(form.get("next"));
      const user = Object.prototype.hasOwnProperty.call(cfg.users, id) ? cfg.users[id] : null;
      if (!user || !(await verifyPassword(String(form.get("password") || ""), user.hash))) {
        return loginForm(nextPath, "ID またはパスワードが違います。");
      }
      const dest = allowed(user, nextPath) ? nextPath : (user.paths || ["/"])[0];
      return new Response(null, { status: 302, headers: { Location: dest, "Cache-Control": "no-store",
        "Set-Cookie": `${COOKIE}=${await makeToken(cfg.secret, id)}; Path=/; Max-Age=${MAX_AGE}; HttpOnly; Secure; SameSite=Lax` } });
    }
    return loginForm(safeNext(url.searchParams.get("next")));
  }

  const id = await readToken(cfg.secret, cookieOf(request));
  const user = id && Object.prototype.hasOwnProperty.call(cfg.users, id) ? cfg.users[id] : null;
  if (!user) {
    return Response.redirect(`${url.origin}${LOGIN}?next=${encodeURIComponent(url.pathname + url.search)}`, 302);
  }
  if (!allowed(user, path)) {
    return page("閲覧できません", `<h1>このページは閲覧できません</h1><p>お使いの ID では、このページを見る権限がありません。</p>
<p><a href="${(user.paths || ["/"])[0]}">見られるページへ</a> ・ <a href="${LOGOUT}">別の ID でログイン</a></p>`, 403);
  }
  const res = await next();
  const out = new Response(res.body, res);
  out.headers.set("Cache-Control", "private, no-store");     // ログインの内側のページを共有キャッシュに残さない
  out.headers.set("X-Robots-Tag", "noindex, nofollow");
  return out;
}
