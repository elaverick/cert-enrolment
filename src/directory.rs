//! LDAP sign-in.
//!
//! A user signs in by binding as themselves. Their membership of the
//! enrollers group is then read over the same connection, so sign-in needs
//! no service account.

use std::time::Duration;

use ldap3::{dn_escape, ldap_escape, LdapConn, LdapConnSettings, LdapError, Scope};

use crate::config::Config;

const TIMEOUT: Duration = Duration::from_secs(5);

/// LDAP result code for a failed bind. ppolicy also returns it for locked
/// accounts, so the two are indistinguishable here by design.
const INVALID_CREDENTIALS: u32 = 49;

pub enum SignIn {
    Allowed,
    NotEnroller,
    InvalidCredentials,
}

/// A user name is a single uid value. Restricting it keeps it safe to place
/// in a DN and a filter, even before escaping.
pub fn valid_username(username: &str) -> bool {
    let valid_chars = username
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b));

    (1..=64).contains(&username.len())
        && valid_chars
        && !username.starts_with(['-', '.'])
}

pub fn sign_in(config: &Config, username: &str, password: &str) -> Result<SignIn, String> {
    // An empty password is an unauthenticated bind, which LDAP accepts.
    if !valid_username(username) || password.is_empty() {
        return Ok(SignIn::InvalidCredentials);
    }

    let settings = LdapConnSettings::new().set_conn_timeout(TIMEOUT);
    let mut ldap = LdapConn::with_settings(settings, &config.ldap_url)
        .map_err(|err| format!("cannot connect to {}: {err}", config.ldap_url))?;

    let user_dn = format!("uid={},{}", dn_escape(username), config.ldap_people_dn);

    let outcome = match ldap.with_timeout(TIMEOUT).simple_bind(&user_dn, password) {
        Ok(result) => match result.success() {
            Ok(_) => is_enroller(&mut ldap, config, username),
            Err(LdapError::LdapResult { result }) if result.rc == INVALID_CREDENTIALS => {
                Ok(SignIn::InvalidCredentials)
            }
            Err(err) => Err(format!("bind failed: {err}")),
        },
        Err(err) => Err(format!("bind failed: {err}")),
    };

    let _ = ldap.unbind();
    outcome
}

fn is_enroller(ldap: &mut LdapConn, config: &Config, username: &str) -> Result<SignIn, String> {
    let filter = format!("(memberUid={})", ldap_escape(username));

    let (entries, _) = ldap
        .with_timeout(TIMEOUT)
        .search(&config.ldap_enrollers_group_dn, Scope::Base, &filter, vec!["1.1"])
        .and_then(|result| result.success())
        .map_err(|err| format!("group lookup failed: {err}"))?;

    Ok(if entries.is_empty() { SignIn::NotEnroller } else { SignIn::Allowed })
}

#[cfg(test)]
mod tests {
    use super::valid_username;

    #[test]
    fn accepts_ordinary_uids() {
        assert!(valid_username("elaverick"));
        assert!(valid_username("t.laverick-2"));
    }

    #[test]
    fn rejects_unsafe_or_empty_uids() {
        for name in ["", "-x", ".x", "Elaverick", "a,b", "a)(uid=*", "a b", "é", &"a".repeat(65)] {
            assert!(!valid_username(name), "{name:?} should be rejected");
        }
    }
}
