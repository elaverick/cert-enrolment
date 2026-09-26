//! Single-use enrolment codes.
//!
//! The portal asks for a code when someone downloads a device's enrolment
//! script, and writes it into the script. The script sends it back with its
//! certificate request. A code names one device, is valid for ten minutes,
//! and is spent once a certificate has been issued with it. Codes are held
//! in memory: a restart invalidates unused ones, and the script is simply
//! downloaded again.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::shared::random::{random_token, tokens_match};

pub const LIFETIME: Duration = Duration::from_secs(10 * 60);

/// Bounds memory use if something requests codes in a loop.
const MAX_CODES: usize = 1000;

struct Pending {
    label: String,
    expires: Instant,
}

#[derive(Default)]
pub struct Codes {
    pending: HashMap<String, Pending>,
}

impl Codes {
    pub fn issue(&mut self, label: &str) -> Result<String, String> {
        self.expire();
        if self.pending.len() >= MAX_CODES {
            return Err("too many unused enrolment codes".to_string());
        }
        let code = random_token()?;
        self.pending.insert(
            code.clone(),
            Pending { label: label.to_string(), expires: Instant::now() + LIFETIME },
        );
        Ok(code)
    }

    /// The device a code is for, if the code is valid. The code stays valid
    /// until spent, so a failed attempt can be retried.
    pub fn device(&mut self, code: &str) -> Option<String> {
        self.expire();
        // Compared in constant time, as codes are secrets.
        self.pending
            .iter()
            .find(|(candidate, _)| tokens_match(candidate, code))
            .map(|(_, pending)| pending.label.clone())
    }

    pub fn spend(&mut self, code: &str) {
        self.pending.remove(code);
    }

    fn expire(&mut self) {
        let now = Instant::now();
        self.pending.retain(|_, pending| pending.expires > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_name_one_device_until_spent() {
        let mut codes = Codes::default();
        let code = codes.issue("tv").unwrap();
        assert_eq!(code.len(), 64);
        assert_eq!(codes.device(&code).as_deref(), Some("tv"));
        assert_eq!(codes.device(&code).as_deref(), Some("tv"));
        assert_eq!(codes.device("wrong"), None);
        codes.spend(&code);
        assert_eq!(codes.device(&code), None);
    }

    #[test]
    fn codes_expire() {
        let mut codes = Codes::default();
        let code = codes.issue("tv").unwrap();
        codes.pending.get_mut(&code).unwrap().expires = Instant::now();
        assert_eq!(codes.device(&code), None);
    }
}
