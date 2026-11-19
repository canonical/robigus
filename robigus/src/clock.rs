//! Fallible access to the current time.
//!
//! `jiff::Timestamp::now()` panics if the system clock is outside jiff's
//! supported range (years -9999 to 9999). Library code must not panic
//! (spec §15), so every timestamp robigus records goes through [`now`].

use std::time::SystemTime;

use crate::error::ClockError;

/// The current time, or an error if the system clock is out of range.
pub(crate) fn now() -> Result<jiff::Timestamp, ClockError> {
    timestamp_from(SystemTime::now())
}

/// The current time as an RFC 3339 UTC string (`...Z`), as stored in the
/// database and written to logs.
pub(crate) fn now_rfc3339() -> Result<String, ClockError> {
    now().map(|timestamp| timestamp.to_string())
}

fn timestamp_from(time: SystemTime) -> Result<jiff::Timestamp, ClockError> {
    jiff::Timestamp::try_from(time).map_err(|error| ClockError(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn current_time_is_rfc3339_utc() {
        let text = now_rfc3339().unwrap();
        assert!(text.ends_with('Z'), "{text}");
        let parsed: jiff::Timestamp = text.parse().unwrap();
        assert!(parsed > jiff::Timestamp::UNIX_EPOCH);
    }

    #[test]
    fn out_of_range_clocks_are_errors_not_panics() {
        // About 12,700 years after and before the Unix epoch.
        let span = Duration::from_secs(400_000_000_000);
        for time in [
            SystemTime::UNIX_EPOCH.checked_add(span),
            SystemTime::UNIX_EPOCH.checked_sub(span),
        ]
        .into_iter()
        .flatten()
        {
            let error = timestamp_from(time).unwrap_err();
            assert!(error.to_string().contains("system clock"), "{error}");
        }
        assert_eq!(
            timestamp_from(SystemTime::UNIX_EPOCH).unwrap(),
            jiff::Timestamp::UNIX_EPOCH
        );
    }
}
