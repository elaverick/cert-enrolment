//! In-memory sessions.
//!
//! A session is identified by a random token in a cookie. Keeping sessions
//! on the server means signing out really ends them. They do not survive a
//! restart, which only means signing in again.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::shared::random::random_token;

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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_sessions_expire_and_removed_sessions_end() {
        let mut sessions = Sessions::new(Duration::from_millis(50));
        let token = sessions.create("alice").unwrap();
        assert_eq!(sessions.get(&token).unwrap().username, "alice");

        sessions.remove(&token);
        assert!(sessions.get(&token).is_none());

        let token = sessions.create("alice").unwrap();
        std::thread::sleep(Duration::from_millis(80));
        assert!(sessions.get(&token).is_none());
    }
}
