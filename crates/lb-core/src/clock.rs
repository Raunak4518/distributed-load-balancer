use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub trait Clock: Send + Sync {
    /// Monotonic time, for measuring *elapsed* intervals (GCRA, circuit
    /// breaker cooldowns). Immune to wall-clock jumps; meaningless across
    /// processes.
    fn now(&self) -> Instant;

    /// Wall-clock seconds since the Unix epoch, for time boundaries that must
    /// be *shared between machines* (cluster bucket alignment). Never use
    /// this to measure elapsed time — it can jump.
    fn unix_secs(&self) -> u64;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            // A clock set before 1970 is pathological; treat it as the epoch
            // rather than panicking on a request path.
            .unwrap_or(0)
    }
}

#[cfg(feature = "test-util")]
pub mod test_util {
    use super::Clock;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    struct FakeState {
        instant: Instant,
        unix_millis: u64,
    }

    #[derive(Clone)]
    pub struct FakeClock {
        state: Arc<Mutex<FakeState>>,
    }

    impl FakeClock {
        pub fn new() -> Self {
            // An arbitrary but realistic epoch base, so bucket numbers in
            // tests look like real timestamps rather than 0, 1, 2.
            Self::with_unix_secs(1_700_000_000)
        }

        pub fn with_unix_secs(unix_secs: u64) -> Self {
            FakeClock {
                state: Arc::new(Mutex::new(FakeState {
                    instant: Instant::now(),
                    unix_millis: unix_secs * 1000,
                })),
            }
        }

        /// Advances monotonic and wall clocks together.
        pub fn advance(&self, d: Duration) {
            let mut guard = self.state.lock().expect("fake clock mutex poisoned");
            guard.instant += d;
            guard.unix_millis += d.as_millis() as u64;
        }
    }

    impl Default for FakeClock {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            self.state
                .lock()
                .expect("fake clock mutex poisoned")
                .instant
        }

        fn unix_secs(&self) -> u64 {
            self.state
                .lock()
                .expect("fake clock mutex poisoned")
                .unix_millis
                / 1000
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn advances_by_exact_duration() {
            let clock = FakeClock::new();
            let start = clock.now();
            clock.advance(Duration::from_secs(5));
            assert_eq!(clock.now().duration_since(start), Duration::from_secs(5));
        }

        #[test]
        fn does_not_advance_on_its_own() {
            let clock = FakeClock::new();
            assert_eq!(clock.now(), clock.now());
            assert_eq!(clock.unix_secs(), clock.unix_secs());
        }

        #[test]
        fn wall_clock_advances_with_monotonic_clock() {
            let clock = FakeClock::with_unix_secs(1_000);
            assert_eq!(clock.unix_secs(), 1_000);
            clock.advance(Duration::from_secs(3));
            assert_eq!(clock.unix_secs(), 1_003);
        }

        #[test]
        fn sub_second_advances_accumulate_into_whole_seconds() {
            let clock = FakeClock::with_unix_secs(1_000);
            clock.advance(Duration::from_millis(600));
            assert_eq!(clock.unix_secs(), 1_000);
            clock.advance(Duration::from_millis(600));
            assert_eq!(clock.unix_secs(), 1_001);
        }
    }
}
