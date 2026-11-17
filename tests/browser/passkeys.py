"""The account website in a real browser: headless Chromium with a virtual
passkey device (Chrome DevTools Protocol, WebAuthn domain).

Signs up with an email code, adds a passkey, signs out, signs in with the
passkey, and approves a computer's code at /device. Run by run.sh, which
starts the server and Chromium:

    python3 passkeys.py <server log file>
"""

import base64
import json
import os
import re
import sys
import time
import urllib.request

from websockets.sync.client import connect

BASE = os.environ.get("BASE", "http://localhost:8480")
LOG = sys.argv[1]


class Page:
    def __init__(self):
        targets = json.load(urllib.request.urlopen("http://127.0.0.1:9222/json"))
        url = next(t for t in targets if t["type"] == "page")["webSocketDebuggerUrl"]
        self.ws = connect(url, max_size=None)
        self.n = 0

    def call(self, method, **params):
        self.n += 1
        self.ws.send(json.dumps({"id": self.n, "method": method, "params": params}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == self.n:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result", {})

    def js(self, expr):
        r = self.call("Runtime.evaluate", expression=expr, awaitPromise=True, returnByValue=True)
        if "exceptionDetails" in r:
            raise RuntimeError(f"{expr}: {r['exceptionDetails']}")
        return r["result"].get("value")

    def goto(self, url):
        self.call("Page.navigate", url=url)
        self.wait_for("document.readyState === 'complete' && !!document.querySelector('main')")

    def wait_for(self, cond, what=None, seconds=10):
        end = time.time() + seconds
        while time.time() < end:
            try:
                if self.js(cond):
                    return
            except RuntimeError:
                pass  # the page is reloading
            time.sleep(0.2)
        raise AssertionError(f"timed out waiting for {what or cond}; message: {self.message()!r}")

    def message(self):
        try:
            return self.js("(document.getElementById('message')||{}).textContent")
        except RuntimeError:
            return None

    def text(self):
        return self.js("document.body.innerText")

    def type(self, el_id, value):
        self.js(f"document.getElementById({json.dumps(el_id)}).value = {json.dumps(value)}")

    def click(self, el_id):
        self.js(f"document.getElementById({json.dumps(el_id)}).click()")


def last_code(email):
    text = re.sub(r"\x1b\[[0-9;]*m", "", open(LOG).read())
    for line in reversed(text.splitlines()):
        if email in line and "code=" in line:
            return re.search(r"code=(\d{6})", line).group(1)
    raise AssertionError("no code in the server log")


def shot(name):
    """Saves a screenshot when SHOTS names a folder."""
    folder = os.environ.get("SHOTS")
    if folder:
        p.call("Emulation.setDeviceMetricsOverride", width=900, height=900, deviceScaleFactor=1, mobile=False)
        data = p.call("Page.captureScreenshot", format="png")["data"]
        with open(os.path.join(folder, name + ".png"), "wb") as f:
            f.write(base64.b64decode(data))


def step(name):
    print(f"[ok] {name}", flush=True)


p = Page()
p.call("Page.enable")
p.call("Runtime.enable")
p.call("WebAuthn.enable")
p.call(
    "WebAuthn.addVirtualAuthenticator",
    options={
        "protocol": "ctap2",
        "transport": "internal",
        "hasResidentKey": True,
        "hasUserVerification": True,
        "isUserVerified": True,
        "automaticPresenceSimulation": True,
    },
)

email = "ana@example.com"
p.goto(BASE + "/")
assert "Sign in with a passkey" in p.text()
shot("1-sign-in")
p.type("email", email)
p.click("email-code")
p.wait_for("!document.getElementById('code-step').hidden", "the code field")
p.type("code", last_code(email))
p.click("code-submit")
p.wait_for("document.body.innerText.includes('Your account')", "the account page")
step("signed up with an email code")

p.click("add-passkey")
p.wait_for("document.body.innerText.includes('1 passkey')", "the new passkey")
step("added a passkey (browser WebAuthn)")
shot("2-account")

p.click("sign-out")
p.wait_for("!!document.getElementById('passkey-login')", "the sign-in page")
step("signed out")

p.type("email", email)
p.click("passkey-login")
p.wait_for("document.body.innerText.includes('Your account')", "signed in again")
step("signed in with the passkey")

# A computer asks to sign in; the person approves its code at /device.
req = urllib.request.Request(
    BASE + "/v1/device/code",
    data=json.dumps({"name": "ana-laptop"}).encode(),
    headers={"content-type": "application/json"},
)
dc = json.load(urllib.request.urlopen(req))
p.goto(f"{BASE}/device?code={dc['user_code']}")
assert p.js("document.getElementById('user-code').value") == dc["user_code"], "code filled in from the address"
p.click("approve-button")
p.wait_for("(document.getElementById('message')||{}).textContent.includes('is signed in')", "the approval")
step("approved a computer's code")
shot("3-device")

# The computer collects its sign-in (it asks every few seconds).
req = urllib.request.Request(
    BASE + "/v1/device/token",
    data=json.dumps({"device_code": dc["device_code"]}).encode(),
    headers={"content-type": "application/json"},
)
assert json.load(urllib.request.urlopen(req))["token"]
p.goto(BASE + "/")
assert "ana-laptop" in p.text(), p.text()
step("the computer is listed on the account page")
shot("4-account-with-computer")
print("OK")
