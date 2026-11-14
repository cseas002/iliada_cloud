//! The whole account flow over HTTP, with a software passkey standing in for
//! a phone or security key: sign up with an email code, add a passkey, sign
//! in with it, approve a computer with a code, keep data, sign the computer
//! out, delete the account.

use std::sync::Arc;

use iliada_account::{AppState, Config, Started, Token, router, store::Store};
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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let origin: Url = format!("http://localhost:{port}").parse().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        origin: origin.clone(),
        data_dir: dir.path().to_owned(),
        log_email_codes: true,
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
