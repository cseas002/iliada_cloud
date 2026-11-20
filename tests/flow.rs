//! The whole account flow over HTTP, with a software passkey standing in for
//! a phone or security key: sign up with an email code, add a passkey, sign
//! in with it, approve a computer with a code, keep data, sign the computer
//! out, delete the account.

use std::sync::Arc;

use iliada_account::mail::Mail;
use iliada_account::store::{SendLimits, Store};
use iliada_account::{AppState, Config, Started, Token, router};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse, Url};

struct Server {
    base: String,
    origin: Url,
    state: Arc<AppState>,
    http: Client,
    _dir: tempfile::TempDir,
}

async fn server(quota: u64) -> Server {
    server_with(quota, Mail::Log, test_limits()).await
}

/// The tests ask for several codes in a row.
fn test_limits() -> SendLimits {
    SendLimits {
        gap_seconds: 0,
        ..SendLimits::default()
    }
}

async fn server_with(quota: u64, mail: Mail, send_limits: SendLimits) -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let origin: Url = format!("http://localhost:{port}").parse().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        origin: origin.clone(),
        data_dir: dir.path().to_owned(),
        mail,
        send_limits,
        quota,
    };
    let state = AppState::new(config, Store::in_memory().unwrap()).unwrap();
    let app = router(state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Server {
        base: format!("http://127.0.0.1:{port}"),
        origin,
        state,
        http: Client::new(),
        _dir: dir,
    }
}

impl Server {
    async fn post(&self, path: &str, token: Option<&str>, body: Value) -> (StatusCode, Value) {
        let mut r = self.http.post(format!("{}{path}", self.base)).json(&body);
        if let Some(t) = token {
            r = r.bearer_auth(t);
        }
        let r = r.send().await.unwrap();
        let status = r.status();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    async fn get(&self, path: &str, token: &str) -> (StatusCode, Value) {
        let r = self
            .http
            .get(format!("{}{path}", self.base))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        let status = r.status();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    /// Signs in with an email code (the code is read from the store, as a
    /// person would read it from the email).
    async fn email_sign_in(&self, email: &str) -> String {
        let (s, _) = self
            .post("/v1/email/start", None, json!({ "email": email }))
            .await;
        assert_eq!(s, StatusCode::NO_CONTENT);
        // The server made a code; make a known one to "read the email".
        let code = self
            .state
            .store
            .new_email_code(&email.to_lowercase())
            .unwrap();
        let (s, v) = self
            .post(
                "/v1/email/finish",
                None,
                json!({ "email": email, "code": code }),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        v["token"].as_str().unwrap().to_owned()
    }
}

#[tokio::test]
async fn sign_up_passkey_computer_data_and_goodbye() {
    let srv = server(1 << 20).await;

    // A wrong code is refused.
    srv.post(
        "/v1/email/start",
        None,
        json!({ "email": "ana@example.com" }),
    )
    .await;
    let (s, _) = srv
        .post(
            "/v1/email/finish",
            None,
            json!({ "email": "ana@example.com", "code": "nope" }),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Sign up with an email code; the address is case-insensitive.
    let web = srv.email_sign_in("Ana@Example.com").await;
    let (s, me) = srv.get("/v1/account", &web).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(me["email"], "ana@example.com");
    assert_eq!(me["passkeys"], 0);

    // No passkey yet: signing in with one is refused plainly.
    let (s, _) = srv
        .post(
            "/v1/passkey/login/start",
            None,
            json!({ "email": "ana@example.com" }),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Add a passkey.
    let mut key = SoftPasskey::new(true);
    let (s, v) = srv
        .post("/v1/passkey/register/start", Some(&web), json!({}))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let started: Started<CreationChallengeResponse> = serde_json::from_value(v).unwrap();
    let credential = key
        .do_registration(srv.origin.clone(), started.options)
        .unwrap();
    let (s, v) = srv
        .post(
            "/v1/passkey/register/finish",
            Some(&web),
            json!({ "flow": started.flow, "credential": credential }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
    assert_eq!(srv.get("/v1/account", &web).await.1["passkeys"], 1);

    // Sign in with it.
    let (s, v) = srv
        .post(
            "/v1/passkey/login/start",
            None,
            json!({ "email": "ana@example.com" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let started: Started<RequestChallengeResponse> = serde_json::from_value(v).unwrap();
    let assertion = key
        .do_authentication(srv.origin.clone(), started.options)
        .unwrap();
    let (s, v) = srv
        .post(
            "/v1/passkey/login/finish",
            None,
            json!({ "flow": started.flow, "credential": assertion }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let web2: Token = serde_json::from_value(v).unwrap();
    assert_eq!(srv.get("/v1/account", &web2.token).await.0, StatusCode::OK);

    // A passkey answer can't be replayed (the ceremony is used up).
    let (s, _) = srv
        .post(
            "/v1/passkey/login/finish",
            None,
            json!({ "flow": started.flow, "credential": assertion }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // A computer asks to sign in and waits.
    let (s, dc) = srv
        .post("/v1/device/code", None, json!({ "name": "ana-laptop" }))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        dc["verification_uri"]
            .as_str()
            .unwrap()
            .ends_with("/device")
    );
    assert_eq!(
        dc["verification_uri_complete"].as_str().unwrap(),
        format!(
            "{}?code={}",
            dc["verification_uri"].as_str().unwrap(),
            dc["user_code"].as_str().unwrap()
        )
    );
    let device = json!({ "device_code": dc["device_code"] });
    assert_eq!(
        srv.post("/v1/device/token", None, device.clone()).await.0,
        StatusCode::PRECONDITION_REQUIRED
    );

    // Ana approves the code on the website.
    let (s, v) = srv
        .post(
            "/v1/device/approve",
            Some(&web),
            json!({ "user_code": dc["user_code"] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["name"], "ana-laptop");
    let (s, v) = srv.post("/v1/device/token", None, device.clone()).await;
    assert_eq!(s, StatusCode::OK);
    let pc = v["token"].as_str().unwrap().to_owned();
    // Handed out once.
    assert_eq!(
        srv.post("/v1/device/token", None, device).await.0,
        StatusCode::BAD_REQUEST
    );

    // The computer can't approve other computers or delete the account.
    let (_, dc2) = srv
        .post("/v1/device/code", None, json!({ "name": "stranger" }))
        .await;
    let (s, _) = srv
        .post(
            "/v1/device/approve",
            Some(&pc),
            json!({ "user_code": dc2["user_code"] }),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let r = srv
        .http
        .delete(format!("{}/v1/account", srv.base))
        .bearer_auth(&pc)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // The computer keeps (encrypted) data and gets it back.
    let blob = format!("{}/v1/blobs/settings.enc", srv.base);
    let put = |body: Vec<u8>| srv.http.put(&blob).bearer_auth(&pc).body(body).send();
    assert_eq!(
        put(vec![7; 1000]).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    let got = srv
        .http
        .get(&blob)
        .bearer_auth(&pc)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(got.as_ref(), &[7; 1000][..]);
    let (_, list) = srv.get("/v1/blobs", &pc).await;
    assert_eq!(list["blobs"][0]["name"], "settings.enc");
    assert_eq!(list["blobs"][0]["size"], 1000);
    // Replacing counts once against the quota; going over it is refused.
    assert_eq!(
        put(vec![8; 900_000]).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    let over = srv
        .http
        .put(format!("{}/v1/blobs/more.enc", srv.base))
        .bearer_auth(&pc)
        .body(vec![0; 200_000]);
    assert_eq!(
        over.send().await.unwrap().status(),
        StatusCode::INSUFFICIENT_STORAGE
    );
    // Names can't leave the account's folder.
    let bad = srv
        .http
        .put(format!("{}/v1/blobs/..%2Fx", srv.base))
        .bearer_auth(&pc)
        .body("x");
    assert_eq!(bad.send().await.unwrap().status(), StatusCode::BAD_REQUEST);

    // Another account sees none of it.
    let bo = srv.email_sign_in("bo@example.com").await;
    let (_, list) = srv.get("/v1/blobs", &bo).await;
    assert_eq!(list["blobs"].as_array().unwrap().len(), 0);
    assert_eq!(
        srv.http
            .get(&blob)
            .bearer_auth(&bo)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );

    // Ana signs the laptop out from the website: its token stops working.
    let (_, me) = srv.get("/v1/account", &web).await;
    let laptop = me["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["kind"] == "computer")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let r = srv
        .http
        .delete(format!("{}/v1/sessions/{laptop}", srv.base))
        .bearer_auth(&web)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert_eq!(srv.get("/v1/blobs", &pc).await.0, StatusCode::UNAUTHORIZED);

    // Bo can't sign out Ana's sessions.
    let (_, me) = srv.get("/v1/account", &web).await;
    let ana_web = me["this_session"].as_str().unwrap().to_owned();
    let r = srv
        .http
        .delete(format!("{}/v1/sessions/{ana_web}", srv.base))
        .bearer_auth(&bo)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);

    // Deleting the account removes it and its data.
    let r = srv
        .http
        .delete(format!("{}/v1/account", srv.base))
        .bearer_auth(&web)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        srv.get("/v1/account", &web2.token).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert!(
        srv.state
            .store
            .account_by_email("ana@example.com")
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn the_website_signs_in_with_a_cookie_and_out_again() {
    let srv = server(1 << 20).await;
    let page = |cookie: Option<String>, path: &'static str| {
        let mut r = srv.http.get(format!("{}{path}", srv.base));
        if let Some(c) = cookie {
            r = r.header("cookie", c);
        }
        r.send()
    };

    // Signed out: the sign-in form, with strict security headers.
    let r = page(None, "/").await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let csp = r.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"),
        "{csp}"
    );
    let body = r.text().await.unwrap();
    assert!(body.contains("Sign in with a passkey") && !body.contains("Your account"));
    assert!(
        page(None, "/device")
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
            .contains("first sign in here")
    );
    for asset in ["/app.js", "/style.css", "/logo.svg"] {
        assert_eq!(
            page(None, asset).await.unwrap().status(),
            StatusCode::OK,
            "{asset}"
        );
    }

    // An email that is HTML stays text.
    srv.post(
        "/v1/email/start",
        None,
        json!({ "email": "x<b>@example.com" }),
    )
    .await;
    let code = srv.state.store.new_email_code("x<b>@example.com").unwrap();
    let r = srv
        .http
        .post(format!("{}/v1/email/finish", srv.base))
        .json(&json!({ "email": "x<b>@example.com", "code": code }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let set = r.headers()["set-cookie"].to_str().unwrap().to_owned();
    assert!(
        set.contains("HttpOnly") && set.contains("SameSite=Strict"),
        "{set}"
    );
    let cookie = set.split(';').next().unwrap().to_owned();

    // Signed in: the account page (escaped), and the computer code form.
    let body = page(Some(cookie.clone()), "/")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("Your account") && body.contains("x&lt;b&gt;@example.com"));
    assert!(!body.contains("x<b>@"));
    assert!(
        page(Some(cookie.clone()), "/device")
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
            .contains("Approve")
    );

    // The cookie works for the API too (the page's buttons), and approves a computer.
    let (_, dc) = srv
        .post("/v1/device/code", None, json!({ "name": "pc" }))
        .await;
    let r = srv
        .http
        .post(format!("{}/v1/device/approve", srv.base))
        .header("cookie", cookie.clone())
        .json(&json!({ "user_code": dc["user_code"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // Sign out: the cookie is cleared and no longer works.
    let r = srv
        .http
        .post(format!("{}/v1/signout", srv.base))
        .header("cookie", cookie.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert!(
        r.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    let body = page(Some(cookie), "/").await.unwrap().text().await.unwrap();
    assert!(body.contains("Sign in with a passkey"));
}

/// A mail server that takes one message and hands its text back.
async fn one_email() -> (u16, tokio::task::JoinHandle<String>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let (r, mut w) = sock.into_split();
        let mut lines = BufReader::new(r).lines();
        w.write_all(b"220 test\r\n").await.unwrap();
        let mut message = String::new();
        let mut in_data = false;
        while let Some(line) = lines.next_line().await.unwrap() {
            if in_data {
                if line == "." {
                    in_data = false;
                    w.write_all(b"250 ok\r\n").await.unwrap();
                } else {
                    message.push_str(&line);
                    message.push('\n');
                }
                continue;
            }
            let verb = line.split_whitespace().next().unwrap_or("").to_uppercase();
            let answer: &[u8] = match verb.as_str() {
                "EHLO" | "HELO" => b"250 test\r\n",
                "DATA" => {
                    in_data = true;
                    b"354 go on\r\n"
                }
                "QUIT" => {
                    w.write_all(b"221 bye\r\n").await.unwrap();
                    break;
                }
                _ => b"250 ok\r\n",
            };
            w.write_all(answer).await.unwrap();
        }
        message
    });
    (port, task)
}

#[tokio::test]
async fn sign_in_codes_are_emailed() {
    let (port, email) = one_email().await;
    let mail = Mail::smtp(
        &format!("smtp://127.0.0.1:{port}"),
        "Iliada <account@example.org>",
    )
    .unwrap();
    let srv = server_with(1 << 20, mail, test_limits()).await;
    let (s, _) = srv
        .post(
            "/v1/email/start",
            None,
            json!({ "email": "Ana@Example.com" }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let message = email.await.unwrap();
    assert!(message.contains("To: ana@example.com"), "{message}");
    assert!(
        message.contains("From: Iliada <account@example.org>"),
        "{message}"
    );
    let code = message
        .lines()
        .find_map(|l| l.strip_prefix("Subject: "))
        .and_then(|s| s.split_whitespace().next())
        .expect("the code in the subject")
        .to_owned();
    assert_eq!(code.len(), 6);
    assert!(message.contains(&format!("    {code}")), "{message}");

    let (s, v) = srv
        .post(
            "/v1/email/finish",
            None,
            json!({ "email": "ana@example.com", "code": code }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["token"].is_string());
}

#[tokio::test]
async fn a_second_code_waits() {
    let srv = server_with(1 << 20, Mail::Log, SendLimits::default()).await;
    let ask = || {
        srv.post(
            "/v1/email/start",
            None,
            json!({ "email": "ana@example.com" }),
        )
    };
    assert_eq!(ask().await.0, StatusCode::NO_CONTENT);
    let (s, v) = ask().await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        v["error"].as_str().unwrap().contains("half a minute"),
        "{v}"
    );
}

impl Server {
    /// A computer signed in to `web`'s account with an approved code.
    async fn computer(&self, web: &str, name: &str) -> String {
        let (_, dc) = self
            .post("/v1/device/code", None, json!({ "name": name }))
            .await;
        let (s, _) = self
            .post(
                "/v1/device/approve",
                Some(web),
                json!({ "user_code": dc["user_code"] }),
            )
            .await;
        assert_eq!(s, StatusCode::OK);
        let (s, v) = self
            .post(
                "/v1/device/token",
                None,
                json!({ "device_code": dc["device_code"] }),
            )
            .await;
        assert_eq!(s, StatusCode::OK);
        v["token"].as_str().unwrap().to_owned()
    }
}

#[tokio::test]
async fn a_signed_in_computer_hands_the_key_to_a_new_one() {
    let srv = server(1 << 20).await;
    let web = srv.email_sign_in("ana@example.com").await;
    let old = srv.computer(&web, "ana-laptop").await;
    let new = srv.computer(&web, "ana-desktop").await;
    let other_web = srv.email_sign_in("bob@example.com").await;
    let bob = srv.computer(&other_web, "bob-pc").await;
    let public_key = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="; // 32 bytes

    // Only computers take part, and a public key is 32 bytes.
    let ask = json!({ "public_key": public_key });
    assert_eq!(
        srv.post("/v1/keys", Some(&web), ask.clone()).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        srv.post("/v1/keys", Some(&new), json!({ "public_key": "AAEC" }))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );

    // The new computer asks; the old one sees it, the asker and others don't.
    let (s, v) = srv.post("/v1/keys", Some(&new), ask.clone()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().unwrap().to_owned();
    let (_, v) = srv.get("/v1/keys", &old).await;
    assert_eq!(v["requests"].as_array().unwrap().len(), 1);
    assert_eq!(v["requests"][0]["computer"], "ana-desktop");
    assert_eq!(v["requests"][0]["public_key"], public_key);
    assert_eq!(
        srv.get("/v1/keys", &new).await.1["requests"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        srv.get("/v1/keys", &bob).await.1["requests"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        srv.get(&format!("/v1/keys/{id}"), &new).await.1["state"],
        "waiting"
    );
    assert_eq!(
        srv.get(&format!("/v1/keys/{id}"), &old).await.0,
        StatusCode::NOT_FOUND
    );

    // Another account, or the asker itself, can't answer.
    let sealed = json!({ "sealed": "c2VhbGVk" });
    let approve = format!("/v1/keys/{id}/approve");
    assert_eq!(
        srv.post(&approve, Some(&bob), sealed.clone()).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        srv.post(&approve, Some(&new), sealed.clone()).await.0,
        StatusCode::NOT_FOUND
    );

    // The old computer answers once; the new one takes it once.
    assert_eq!(
        srv.post(&approve, Some(&old), sealed.clone()).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        srv.post(&approve, Some(&old), sealed).await.0,
        StatusCode::CONFLICT
    );
    let (s, v) = srv.get(&format!("/v1/keys/{id}"), &new).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["state"], "answered");
    assert_eq!(v["sealed"], "c2VhbGVk");
    assert_eq!(
        srv.get(&format!("/v1/keys/{id}"), &new).await.0,
        StatusCode::NOT_FOUND
    );

    // Asked again and refused.
    let id = srv.post("/v1/keys", Some(&new), ask).await.1["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        srv.post(&format!("/v1/keys/{id}/refuse"), Some(&old), json!({}))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        srv.get("/v1/keys", &old).await.1["requests"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        srv.get(&format!("/v1/keys/{id}"), &new).await.1["state"],
        "refused"
    );
}
