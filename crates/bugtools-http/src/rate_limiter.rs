use std::time::{Duration, Instant};

/// Token-bucket rate limiter with burst capacity and sustained refill.
///
/// Enforces `rate_limit_rps` from `HttpClientConfig` — previously declared
/// but never enforced. Thread-safe via interior mutability (`Mutex`),
/// clamped so a panic while holding the lock cannot poison the client.
#[derive(Debug)]
pub struct TokenBucket {
    capacity: f64,
    refill_per_second: f64,
    state: std::sync::Mutex<BucketState>,
}

#[derive(Debug)]
struct BucketState {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a bucket that allows `burst` immediate requests and then
    /// sustains `refill_per_second` requests per second indefinitely.
    ///
    /// Panics if burst or refill are non-positive — callers pass config
    /// constants, and a silently-permissive limiter would be a safety bug.
    pub fn new(burst: f64, refill_per_second: f64) -> Self {
        assert!(burst > 0.0, "token bucket burst must be positive");
        assert!(refill_per_second > 0.0, "token bucket refill rate must be positive");
        Self {
            capacity: burst,
            refill_per_second,
            state: std::sync::Mutex::new(BucketState {
                tokens: burst,
                last_refill: Instant::now(),
            }),
        }
    }

    fn refill(&self, state: &mut BucketState) {
        let now = Instant::now();
        let elapsed = now.duration_since(state.last_refill).as_secs_f64();
        if elapsed <= 0.0 {
            return;
        }
        state.tokens = (state.tokens + elapsed * self.refill_per_second).min(self.capacity);
        state.last_refill = now;
    }

    /// Synchronously attempt to consume one token.
    /// Returns `true` when the request may proceed immediately.
    pub fn try_acquire(&self) -> bool {
        let mut state = match self.state.lock() {
            Ok(s) => s,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.refill(&mut state);
        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Milliseconds to wait until the next token is available.
    /// Returns `Duration::ZERO` when a token is available now.
    pub fn wait_duration(&self) -> Duration {
        let mut state = match self.state.lock() {
            Ok(s) => s,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.refill(&mut state);
        if state.tokens >= 1.0 {
            return Duration::ZERO;
        }
        let deficit = 1.0 - state.tokens;
        let secs = deficit / self.refill_per_second;
        Duration::from_secs_f64(secs)
    }

    /// Current token count (refilled lazily). For status reporting / UI.
    pub fn available_tokens(&self) -> f64 {
        let mut state = match self.state.lock() {
            Ok(s) => s,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.refill(&mut state);
        state.tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_capacity_then_throttle() {
        let bucket = TokenBucket::new(3.0, 100.0); // fast refill for test
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        // Bucket exhausted — must be denied before refill accumulates.
        assert!(!bucket.try_acquire());
    }

    #[test]
    fn refill_recovers_over_time() {
        let bucket = TokenBucket::new(1.0, 50.0);
        assert!(bucket.try_acquire());
        assert!(!bucket.try_acquire());
        std::thread::sleep(Duration::from_millis(40));
        // ~2 tokens refilled at 50/s in 40ms — at least one must be there.
        assert!(bucket.try_acquire());
    }

    #[test]
    fn wait_duration_reports_realistic_delay() {
        let bucket = TokenBucket::new(1.0, 10.0);
        assert!(bucket.try_acquire());
        let wait = bucket.wait_duration();
        assert!(wait > Duration::ZERO);
        assert!(wait <= Duration::from_millis(1000));
    }
}
