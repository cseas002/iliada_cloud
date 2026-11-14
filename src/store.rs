//! What the account server keeps: accounts, their passkeys, sign-ins
//! (sessions), one-time codes, and how much each account stores.
//!
//! One SQLite file. Secrets the server hands out (session tokens, codes) are
//! kept only as SHA-256 hashes, so a copy of the database can't be used to
//! sign in. Blobs (the encrypted data people keep) are files next to it.

use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use webauthn_rs::prelude::{Passkey, Uuid};

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// SHA-256 of a secret, in hex: how tokens and codes are stored.
pub fn hash(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

/// A random secret: 32 bytes, URL-safe base64.
pub fn secret() -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub id: String,
    pub email: String,
    pub created: i64,
}

/// A signed-in browser ("web") or computer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Session {
    pub id: String,
    pub account: String,
    pub kind: Kind,
    pub name: String,
    pub created: i64,
    pub last_used: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// The account website: may approve computers and change the account.
    Web,
    /// A computer: may keep and fetch its owner's data.
    Computer,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Web => "web",
            Kind::Computer => "computer",
        }
    }
    fn parse(s: &str) -> Kind {
        if s == "web" {
            Kind::Web
        } else {
            Kind::Computer
        }
    }
}

/// What happened to a device code.
#[derive(Debug, PartialEq, Eq)]
pub enum DeviceState {
    Pending,
    /// Approved: the computer's session token (handed out once).
    Approved(String),
    Expired,
    Unknown,
}

pub struct Store {
    db: Mutex<Connection>,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS passkeys (
  cred_id TEXT PRIMARY KEY,
  account TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  passkey TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
  account TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, name TEXT NOT NULL,
  created INTEGER NOT NULL, last_used INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS email_codes (
  email TEXT PRIMARY KEY, code_hash TEXT NOT NULL,
  expires INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS device_codes (
  device_hash TEXT PRIMARY KEY, user_code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL, expires INTEGER NOT NULL,
  account TEXT);
";

/// How long a one-time code is valid, and how many wrong tries it takes.
pub const CODE_SECONDS: i64 = 10 * 60;
pub const CODE_TRIES: i64 = 5;
pub const DEVICE_SECONDS: i64 = 15 * 60;

impl Store {
    pub fn open(path: &Path) -> Result<Store> {
        let db = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        Self::init(db)
    }

    pub fn in_memory() -> Result<Store> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(db: Connection) -> Result<Store> {
        db.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")?;
        db.execute_batch(SCHEMA)?;
        Ok(Store { db: Mutex::new(db) })
    }

    fn db(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ── Accounts ──────────────────────────────────────────────────────

    pub fn account_by_email(&self, email: &str) -> Result<Option<Account>> {
        Ok(self
            .db()
            .query_row(
                "SELECT id, email, created FROM accounts WHERE email = ?1",
                [email],
                |r| {
                    Ok(Account {
                        id: r.get(0)?,
                        email: r.get(1)?,
                        created: r.get(2)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn account(&self, id: &str) -> Result<Option<Account>> {
        Ok(self
            .db()
            .query_row(
                "SELECT id, email, created FROM accounts WHERE id = ?1",
                [id],
                |r| {
                    Ok(Account {
                        id: r.get(0)?,
                        email: r.get(1)?,
                        created: r.get(2)?,
                    })
                },
            )
            .optional()?)
    }

    /// The account for this (verified) email, made if there is none.
    pub fn account_for_email(&self, email: &str) -> Result<Account> {
        if let Some(a) = self.account_by_email(email)? {
            return Ok(a);
        }
        let a = Account {
            id: Uuid::new_v4().to_string(),
            email: email.to_owned(),
            created: now(),
        };
        self.db().execute(
            "INSERT INTO accounts (id, email, created) VALUES (?1, ?2, ?3)",
            params![a.id, a.email, a.created],
        )?;
        Ok(a)
    }

    pub fn delete_account(&self, id: &str) -> Result<()> {
        self.db()
            .execute("DELETE FROM accounts WHERE id = ?1", [id])?;
        Ok(())
    }

    // ── Passkeys ──────────────────────────────────────────────────────

    pub fn passkeys(&self, account: &str) -> Result<Vec<Passkey>> {
        let db = self.db();
        let mut q =
            db.prepare("SELECT passkey FROM passkeys WHERE account = ?1 ORDER BY created")?;
        let rows = q.query_map([account], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for json in rows {
            out.push(serde_json::from_str(&json?)?);
        }
        Ok(out)
    }

    /// Adds a passkey, or saves its new state (its sign-in counter).
    pub fn save_passkey(&self, account: &str, pk: &Passkey) -> Result<()> {
        let id = hex::encode(pk.cred_id().as_slice());
        self.db().execute(
            "INSERT INTO passkeys (cred_id, account, passkey, created) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(cred_id) DO UPDATE SET passkey = excluded.passkey WHERE account = excluded.account",
            params![id, account, serde_json::to_string(pk)?, now()],
        )?;
        Ok(())
    }

    // ── Sessions ──────────────────────────────────────────────────────

    /// Starts a session; returns its token (shown once, stored hashed).
    pub fn new_session(&self, account: &str, kind: Kind, name: &str) -> Result<String> {
        let token = secret();
        let t = now();
        self.db().execute(
            "INSERT INTO sessions (id, token_hash, account, kind, name, created, last_used)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
            params![
                Uuid::new_v4().to_string(),
                hash(&token),
                account,
                kind.as_str(),
                name,
                t
            ],
        )?;
        Ok(token)
    }

    pub fn session(&self, token: &str) -> Result<Option<Session>> {
        let db = self.db();
        let s = db
            .query_row(
                "SELECT id, account, kind, name, created, last_used FROM sessions WHERE token_hash = ?1",
                [hash(token)],
                |r| {
                    Ok(Session {
                        id: r.get(0)?,
                        account: r.get(1)?,
                        kind: Kind::parse(&r.get::<_, String>(2)?),
                        name: r.get(3)?,
                        created: r.get(4)?,
                        last_used: r.get(5)?,
                    })
                },
            )
            .optional()?;
        if let Some(s) = &s {
            db.execute(
                "UPDATE sessions SET last_used = ?1 WHERE id = ?2",
                params![now(), s.id],
            )?;
        }
        Ok(s)
    }

    pub fn sessions(&self, account: &str) -> Result<Vec<Session>> {
        let db = self.db();
        let mut q = db.prepare(
            "SELECT id, account, kind, name, created, last_used FROM sessions WHERE account = ?1 ORDER BY created",
        )?;
        let rows = q.query_map([account], |r| {
            Ok(Session {
                id: r.get(0)?,
                account: r.get(1)?,
                kind: Kind::parse(&r.get::<_, String>(2)?),
                name: r.get(3)?,
                created: r.get(4)?,
                last_used: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Ends one of the account's sessions; false if it has no such session.
    pub fn end_session(&self, account: &str, id: &str) -> Result<bool> {
        Ok(self.db().execute(
            "DELETE FROM sessions WHERE id = ?1 AND account = ?2",
            [id, account],
        )? > 0)
    }

    // ── Email codes ───────────────────────────────────────────────────

    /// A new six-digit code for this email (replacing any earlier one).
    pub fn new_email_code(&self, email: &str) -> Result<String> {
        let code = format!("{:06}", rand::random_range(0..1_000_000u32));
        self.db().execute(
            "INSERT INTO email_codes (email, code_hash, expires, attempts) VALUES (?1, ?2, ?3, 0)
             ON CONFLICT(email) DO UPDATE SET code_hash = excluded.code_hash, expires = excluded.expires, attempts = 0",
            params![email, hash(&format!("{email}:{code}")), now() + CODE_SECONDS],
        )?;
        Ok(code)
    }

    /// Checks a code; a right one is used up, too many wrong ones void it.
    pub fn check_email_code(&self, email: &str, code: &str) -> Result<bool> {
        let db = self.db();
        let row: Option<(String, i64, i64)> = db
            .query_row(
                "SELECT code_hash, expires, attempts FROM email_codes WHERE email = ?1",
                [email],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((h, expires, attempts)) = row else {
            return Ok(false);
        };
        if expires < now() || attempts >= CODE_TRIES {
            db.execute("DELETE FROM email_codes WHERE email = ?1", [email])?;
            return Ok(false);
        }
        if h == hash(&format!("{email}:{}", code.trim())) {
            db.execute("DELETE FROM email_codes WHERE email = ?1", [email])?;
            return Ok(true);
        }
        db.execute(
            "UPDATE email_codes SET attempts = attempts + 1 WHERE email = ?1",
            [email],
        )?;
        Ok(false)
    }

    // ── Computers signing in (device codes) ──────────────────────────

    /// A computer asks to sign in: (device code it keeps, code the person types).
    pub fn new_device_code(&self, name: &str) -> Result<(String, String)> {
        let device = secret();
        // Eight letters people can read aloud: no 0/O, 1/I/L.
        const ABC: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
        let user: String = (0..8)
            .map(|_| ABC[rand::random_range(0..ABC.len())] as char)
            .collect();
        let user = format!("{}-{}", &user[..4], &user[4..]);
        let db = self.db();
        db.execute("DELETE FROM device_codes WHERE expires < ?1", [now()])?;
        db.execute(
            "INSERT INTO device_codes (device_hash, user_code, name, expires) VALUES (?1, ?2, ?3, ?4)",
            params![hash(&device), user, name, now() + DEVICE_SECONDS],
        )?;
        Ok((device, user))
    }

    /// The person approves a computer's code: the computer gets a session.
    /// Returns the computer's name, or None for an unknown or expired code.
    pub fn approve_device(&self, user_code: &str, account: &str) -> Result<Option<String>> {
        let user_code = user_code.trim().to_ascii_uppercase();
        let row: Option<(String, i64, Option<String>)> = self
            .db()
            .query_row(
                "SELECT name, expires, account FROM device_codes WHERE user_code = ?1",
                [&user_code],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((name, expires, approved)) = row else {
            return Ok(None);
        };
        if expires < now() || approved.is_some() {
            return Ok(None);
        }
        self.db().execute(
            "UPDATE device_codes SET account = ?1 WHERE user_code = ?2",
            params![account, user_code],
        )?;
        Ok(Some(name))
    }

    /// The computer asks whether it was approved. Its session is made now, so
    /// the token never sits in the database; it is handed out once.
    pub fn poll_device(&self, device: &str) -> Result<DeviceState> {
        let row: Option<(i64, String, Option<String>)> = self
            .db()
            .query_row(
                "SELECT expires, name, account FROM device_codes WHERE device_hash = ?1",
                [hash(device)],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        Ok(match row {
            None => DeviceState::Unknown,
            Some((_, name, Some(account))) => {
                self.db().execute(
                    "DELETE FROM device_codes WHERE device_hash = ?1",
                    [hash(device)],
                )?;
                DeviceState::Approved(self.new_session(&account, Kind::Computer, &name)?)
            }
            Some((expires, _, None)) if expires < now() => DeviceState::Expired,
            Some(_) => DeviceState::Pending,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounts_are_made_once_per_email() {
        let s = Store::in_memory().unwrap();
        let a = s.account_for_email("ana@example.com").unwrap();
        assert_eq!(s.account_for_email("ana@example.com").unwrap(), a);
        assert_ne!(s.account_for_email("bo@example.com").unwrap().id, a.id);
    }

    #[test]
    fn sessions_are_found_by_token_only() {
        let s = Store::in_memory().unwrap();
        let a = s.account_for_email("ana@example.com").unwrap();
        let t = s.new_session(&a.id, Kind::Web, "Firefox").unwrap();
        let found = s.session(&t).unwrap().unwrap();
        assert_eq!(
            (found.account.as_str(), found.kind),
            (a.id.as_str(), Kind::Web)
        );
        assert!(s.session("not-a-token").unwrap().is_none());
        // Ended: gone.
        assert!(s.end_session(&a.id, &found.id).unwrap());
        assert!(s.session(&t).unwrap().is_none());
    }

    #[test]
    fn email_codes_work_once_and_not_after_five_wrong_tries() {
        let s = Store::in_memory().unwrap();
        let c = s.new_email_code("ana@example.com").unwrap();
        assert!(
            !s.check_email_code("bo@example.com", &c).unwrap(),
            "another email's code"
        );
        assert!(s.check_email_code("ana@example.com", &c).unwrap());
        assert!(
            !s.check_email_code("ana@example.com", &c).unwrap(),
            "used up"
        );

        let c = s.new_email_code("ana@example.com").unwrap();
        let wrong = if c == "000000" { "111111" } else { "000000" };
        for _ in 0..CODE_TRIES {
            assert!(!s.check_email_code("ana@example.com", wrong).unwrap());
        }
        assert!(
            !s.check_email_code("ana@example.com", &c).unwrap(),
            "voided by wrong tries"
        );
    }

    #[test]
    fn a_computer_gets_its_token_once_after_approval() {
        let s = Store::in_memory().unwrap();
        let a = s.account_for_email("ana@example.com").unwrap();
        let (device, user) = s.new_device_code("ana-laptop").unwrap();
        assert_eq!(user.len(), 9);
        assert_eq!(s.poll_device(&device).unwrap(), DeviceState::Pending);
        assert_eq!(
            s.approve_device(&user.to_lowercase(), &a.id)
                .unwrap()
                .as_deref(),
            Some("ana-laptop")
        );
        assert_eq!(
            s.approve_device(&user, &a.id).unwrap(),
            None,
            "approved once"
        );
        let DeviceState::Approved(token) = s.poll_device(&device).unwrap() else {
            panic!("not approved")
        };
        assert_eq!(s.session(&token).unwrap().unwrap().kind, Kind::Computer);
        assert_eq!(
            s.poll_device(&device).unwrap(),
            DeviceState::Unknown,
            "handed out once"
        );
        assert_eq!(s.approve_device("NOPE-NOPE", &a.id).unwrap(), None);
    }

    #[test]
    fn deleting_an_account_ends_its_sessions() {
        let s = Store::in_memory().unwrap();
        let a = s.account_for_email("ana@example.com").unwrap();
        let t = s.new_session(&a.id, Kind::Computer, "pc").unwrap();
        s.delete_account(&a.id).unwrap();
        assert!(s.session(&t).unwrap().is_none());
        assert!(s.account(&a.id).unwrap().is_none());
    }
}
