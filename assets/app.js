// The account website's buttons. Passkeys use the browser's WebAuthn API;
// the server's options and the browser's answers travel as JSON with binary
// fields in base64url. The sign-in itself is an HttpOnly cookie this script
// never sees.
"use strict";

const b64 = {
  toBuf(s) {
    const pad = "=".repeat((4 - (s.length % 4)) % 4);
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
    return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
  },
  fromBuf(buf) {
    let bin = "";
    for (const b of new Uint8Array(buf)) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
};

const $ = (id) => document.getElementById(id);

function say(text, isError) {
  const m = $("message");
  if (!m) return;
  m.textContent = text;
  m.classList.toggle("error", !!isError);
}

async function api(method, path, body) {
  const r = await fetch(path, {
    method,
    headers: body === undefined ? {} : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
  });
  let data = null;
  try {
    data = await r.json();
  } catch (_) {
    /* no body */
  }
  if (!r.ok) throw new Error((data && data.error) || `the server answered ${r.status}`);
  return data;
}

function busy(button, on) {
  if (button) button.disabled = on;
}

// ── Passkeys ──────────────────────────────────────────────────────────

const passkeysWork = () => !!(window.PublicKeyCredential && navigator.credentials);

function creationOptions(o) {
  const pk = structuredClone(o.publicKey);
  pk.challenge = b64.toBuf(pk.challenge);
  pk.user.id = b64.toBuf(pk.user.id);
  for (const c of pk.excludeCredentials || []) c.id = b64.toBuf(c.id);
  return { publicKey: pk };
}

function requestOptions(o) {
  const pk = structuredClone(o.publicKey);
  pk.challenge = b64.toBuf(pk.challenge);
  for (const c of pk.allowCredentials || []) c.id = b64.toBuf(c.id);
  return { publicKey: pk };
}

function registration(cred) {
  return {
    id: cred.id,
    rawId: b64.fromBuf(cred.rawId),
    type: cred.type,
    response: {
      attestationObject: b64.fromBuf(cred.response.attestationObject),
      clientDataJSON: b64.fromBuf(cred.response.clientDataJSON),
      transports: cred.response.getTransports ? cred.response.getTransports() : undefined,
    },
    extensions: cred.getClientExtensionResults(),
  };
}

function assertion(cred) {
  const r = cred.response;
  return {
    id: cred.id,
    rawId: b64.fromBuf(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: b64.fromBuf(r.authenticatorData),
      clientDataJSON: b64.fromBuf(r.clientDataJSON),
      signature: b64.fromBuf(r.signature),
      userHandle: r.userHandle ? b64.fromBuf(r.userHandle) : null,
    },
    extensions: cred.getClientExtensionResults(),
  };
}

function passkeyError(e) {
  // The person closed the browser's passkey window, or it timed out.
  if (e && e.name === "NotAllowedError") return "The passkey wasn't used. Try again when you're ready.";
  return e.message || String(e);
}

// ── Signing in ────────────────────────────────────────────────────────

function email() {
  const v = $("email").value.trim();
  if (!v) {
    say("Enter your email first.", true);
    $("email").focus();
    return null;
  }
  return v;
}

async function passkeyLogin(ev) {
  const button = ev.currentTarget;
  const e = email();
  if (!e) return;
  if (!passkeysWork()) return say("This browser can't use passkeys. Use “Email me a code”.", true);
  busy(button, true);
  try {
    const started = await api("POST", "/v1/passkey/login/start", { email: e });
    const cred = await navigator.credentials.get(requestOptions(started.options));
    await api("POST", "/v1/passkey/login/finish", { flow: started.flow, credential: assertion(cred) });
    location.reload();
  } catch (err) {
    say(passkeyError(err), true);
  } finally {
    busy(button, false);
  }
}

async function emailCode(ev) {
  const button = ev.currentTarget;
  const e = email();
  if (!e) return;
  busy(button, true);
  try {
    await api("POST", "/v1/email/start", { email: e });
    $("code-step").hidden = false;
    $("code").focus();
    say(`We emailed a code to ${e}. It works for 10 minutes.`);
  } catch (err) {
    say(err.message, true);
  } finally {
    busy(button, false);
  }
}

async function codeSubmit(ev) {
  const button = ev.currentTarget;
  const e = email();
  if (!e) return;
  busy(button, true);
  try {
    await api("POST", "/v1/email/finish", { email: e, code: $("code").value.trim() });
    location.reload();
  } catch (err) {
    say(err.message, true);
  } finally {
    busy(button, false);
  }
}

// ── The account ───────────────────────────────────────────────────────

async function addPasskey(ev) {
  const button = ev.currentTarget;
  if (!passkeysWork()) return say("This browser can't make passkeys.", true);
  busy(button, true);
  try {
    const started = await api("POST", "/v1/passkey/register/start", {});
    const cred = await navigator.credentials.create(creationOptions(started.options));
    await api("POST", "/v1/passkey/register/finish", { flow: started.flow, credential: registration(cred) });
    location.reload();
  } catch (err) {
    say(passkeyError(err), true);
  } finally {
    busy(button, false);
  }
}

async function endSession(ev) {
  const button = ev.currentTarget;
  busy(button, true);
  try {
    await api("DELETE", `/v1/sessions/${encodeURIComponent(button.dataset.endSession)}`);
    location.reload();
  } catch (err) {
    say(err.message, true);
    busy(button, false);
  }
}

async function signOut() {
  try {
    await api("POST", "/v1/signout");
  } finally {
    location.reload();
  }
}

async function deleteAccount() {
  if (!confirm("Delete your Iliada account and everything it keeps? This can't be undone.")) return;
  try {
    await api("DELETE", "/v1/account");
    location.reload();
  } catch (err) {
    say(err.message, true);
  }
}

// ── A computer's code ─────────────────────────────────────────────────

async function approve(ev) {
  const button = ev.currentTarget;
  const code = $("user-code").value.trim().toUpperCase();
  if (!code) return say("Type the code your computer shows.", true);
  busy(button, true);
  try {
    const r = await api("POST", "/v1/device/approve", { user_code: code });
    $("user-code").value = "";
    say(`“${r.name}” is signed in. You can close this page.`);
  } catch (err) {
    say(err.message, true);
  } finally {
    busy(button, false);
  }
}

// ── Wiring ────────────────────────────────────────────────────────────

function on(id, handler) {
  const el = $(id);
  if (el) el.addEventListener("click", handler);
}

function enterSubmits(inputId, buttonId) {
  const input = $(inputId);
  if (input) input.addEventListener("keydown", (e) => e.key === "Enter" && $(buttonId).click());
}

document.addEventListener("DOMContentLoaded", () => {
  on("passkey-login", passkeyLogin);
  on("email-code", emailCode);
  on("code-submit", codeSubmit);
  on("add-passkey", addPasskey);
  on("sign-out", signOut);
  on("delete-account", deleteAccount);
  on("approve-button", approve);
  enterSubmits("code", "code-submit");
  enterSubmits("user-code", "approve-button");
  for (const b of document.querySelectorAll("[data-end-session]")) b.addEventListener("click", endSession);

  // A code in the address (/device?code=ABCD-EFGH) is filled in.
  const code = new URLSearchParams(location.search).get("code");
  if (code && $("user-code")) $("user-code").value = code.slice(0, 9).toUpperCase();

  // "Last used" times in the person's own words and time zone.
  for (const el of document.querySelectorAll("[data-time]")) {
    const t = new Date(Number(el.dataset.time) * 1000);
    const when = t.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
    el.textContent = el.textContent ? `${el.textContent} · last used ${when}` : `last used ${when}`;
  }
});
