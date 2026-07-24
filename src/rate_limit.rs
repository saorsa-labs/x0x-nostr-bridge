//! Per-principal fixed-window HTTP rate limiter (dialect.md §5). Owner: wp2-http.
//!
//! Default-off: the daemon only calls [`RateLimiter::check`] when
//! `Settings::rate_limit_per_min` is `Some`. The 429 body grammar
//! (`rate-limited: ... retry in <N>s`) is emitted by the HTTP layer regardless.

use std::collections::HashMap;

use parking_lot::Mutex;

const WINDOW_SECS: u64 = 60;

/// Fixed 60-second window per principal.
#[derive(Default)]
pub struct RateLimiter {
    windows: Mutex<HashMap<String, (u64, u32)>>, // principal -> (window_start, count)
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit one request for `principal`. `Err(retry_secs)` when the per-minute
    /// `quota` is exceeded; `retry_secs` is the seconds until the window rolls.
    pub fn check(&self, principal: &str, quota: u32, now: u64) -> Result<(), u64> {
        let mut windows = self.windows.lock();
        let entry = windows.entry(principal.to_string()).or_insert((now, 0));
        if now.saturating_sub(entry.0) >= WINDOW_SECS {
            *entry = (now, 0);
        }
        if entry.1 >= quota {
            let retry = WINDOW_SECS.saturating_sub(now.saturating_sub(entry.0)).max(1);
            return Err(retry);
        }
        entry.1 += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_up_to_quota_then_429s() {
        let rl = RateLimiter::new();
        // quota 2 in the window
        assert!(rl.check("alice", 2, 100).is_ok());
        assert!(rl.check("alice", 2, 100).is_ok());
        let retry = rl.check("alice", 2, 100).unwrap_err();
        assert!(retry >= 1 && retry <= 60);
        // a different principal is independent
        assert!(rl.check("bob", 2, 100).is_ok());
    }

    #[test]
    fn window_rolls_over() {
        let rl = RateLimiter::new();
        assert!(rl.check("alice", 1, 100).is_ok());
        assert!(rl.check("alice", 1, 100).is_err());
        // next window
        assert!(rl.check("alice", 1, 160).is_ok());
    }
}
