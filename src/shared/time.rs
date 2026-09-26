//! UTC times as LDAP GeneralizedTime, `YYYYMMDDHHMMSSZ`, the form the RA
//! records certificate expiry in.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// Seconds since the Unix epoch as `YYYYMMDDHHMMSSZ`.
pub fn generalized_time(unix: i64) -> Result<String, String> {
    if unix < 0 {
        return Err("time before 1970".to_string());
    }
    let days = unix / 86_400;
    let seconds = unix % 86_400;

    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);

    Ok(format!(
        "{year:04}{month:02}{day:02}{:02}{:02}{:02}Z",
        seconds / 3_600,
        seconds % 3_600 / 60,
        seconds % 60
    ))
}

/// A `YYYYMMDDHHMMSSZ` time as seconds since the Unix epoch.
pub fn parse_generalized_time(text: &str) -> Option<i64> {
    let digits = text.strip_suffix('Z')?;
    if digits.len() != 14 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let field = |range: std::ops::Range<usize>| digits[range].parse::<i64>().ok();
    let (year, month, day) = (field(0..4)?, field(4..6)?, field(6..8)?);
    let (hour, minute, second) = (field(8..10)?, field(10..12)?, field(12..14)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    // Days since 1970-01-01 from a civil date (Howard Hinnant's algorithm).
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;

    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_generalized_time() {
        assert_eq!(generalized_time(0).unwrap(), "19700101000000Z");
        assert_eq!(generalized_time(951_782_400).unwrap(), "20000229000000Z");
        assert_eq!(generalized_time(1_793_024_071).unwrap(), "20261026141431Z");
        assert!(generalized_time(-1).is_err());
    }

    #[test]
    fn parses_generalized_time() {
        for unix in [0, 951_782_400, 1_793_024_071, 4_102_444_799] {
            assert_eq!(parse_generalized_time(&generalized_time(unix).unwrap()), Some(unix));
        }
        for text in ["", "20261026141431", "2026102614143Z", "20261326141431Z", "2026102614143xZ"] {
            assert_eq!(parse_generalized_time(text), None, "{text:?} should be refused");
        }
    }
}
