//! User names, as they appear in LDAP uid values.

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

#[cfg(test)]
mod tests {
    use super::valid_username;

    #[test]
    fn accepts_ordinary_uids() {
        assert!(valid_username("alice"));
        assert!(valid_username("b.smith-2"));
    }

    #[test]
    fn rejects_unsafe_or_empty_uids() {
        for name in ["", "-x", ".x", "Alice", "a,b", "a)(uid=*", "a b", "é", &"a".repeat(65)] {
            assert!(!valid_username(name), "{name:?} should be rejected");
        }
    }
}
