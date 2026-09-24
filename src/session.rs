//! In-memory sessions.
//!
//! A session is identified by a random token in a cookie. Keeping sessions
//! on the server means signing out really ends them. They do not survive a
//! restart, which only means signing in again.

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::time::{Duration, Instant};

/// Bounds memory use if something creates sessions in a loop.
const MAX_SESSIONS: usize = 1000;

pub struct Session {
    pub username: String,
    /// Must accompany every form submission made within the session.
    pub csrf_token: String,
    last_seen: Instant,
}

pub struct Sessions {
    idle: Duration,
    sessions: HashMap<String, Session>,
}

impl Sessions {
    pub fn new(idle: Duration) -> Sessions {
        Sessions { idle, sessions: HashMap::new() }
    }

    /// Creates a session and returns its token.
    pub fn create(&mut self, username: &str) -> Result<String, String> {
        self.expire();
        if self.sessions.len() >= MAX_SESSIONS {
            return Err("too many active sessions".to_string());
        }

        let token = random_token()?;
        self.sessions.insert(
            token.clone(),
            Session {
                username: username.to_string(),
                csrf_token: random_token()?,
                last_seen: Instant::now(),
            },
        );
        Ok(token)
    }

    /// Looks up a live session and marks it as used.
    pub fn get(&mut self, token: &str) -> Option<&Session> {
        self.expire();
        let session = self.sessions.get_mut(token)?;
        session.last_seen = Instant::now();
        Some(session)
    }

    pub fn remove(&mut self, token: &str) {
        self.sessions.remove(token);
    }

    fn expire(&mut self) {
        let idle = self.idle;
        self.sessions.retain(|_, session| session.last_seen.elapsed() < idle);
    }
}

/// 256 bits from the kernel CSPRNG, hex encoded.
pub fn random_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut urandom| urandom.read_exact(&mut bytes))
        .map_err(|err| format!("cannot read /dev/urandom: {err}"))?;

    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Compares secrets without leaking, through timing, how much matched.
pub fn tokens_match(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_hex() {
        let a = random_token().unwrap();
        let b = random_token().unwrap();
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn token_comparison() {
        assert!(tokens_match("abc", "abc"));
        assert!(!tokens_match("abc", "abd"));
        assert!(!tokens_match("abc", "abcd"));
    }

    #[test]
    fn idle_sessions_expire_and_removed_sessions_end() {
        let mut sessions = Sessions::new(Duration::from_millis(50));
        let token = sessions.create("elaverick").unwrap();
        assert_eq!(sessions.get(&token).unwrap().username, "elaverick");

        sessions.remove(&token);
        assert!(sessions.get(&token).is_none());

        let token = sessions.create("elaverick").unwrap();
        std::thread::sleep(Duration::from_millis(80));
        assert!(sessions.get(&token).is_none());
    }
}
