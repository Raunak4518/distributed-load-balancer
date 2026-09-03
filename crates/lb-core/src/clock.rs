use std::time::Instant;

pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[cfg(feature = "test-util")]
pub mod test_util {
    use super::Clock;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    #[derive(Clone)]
    pub struct FakeClock {
        current: Arc<Mutex<Instant>>,
    }

    impl FakeClock {
        pub fn new() -> Self {
            FakeClock {
                current: Arc::new(Mutex::new(Instant::now())),
            }
        }

        pub fn advance(&self, d: std::time::Duration) {
            let mut guard = self.current.lock().expect("fake clock mutex poisoned");
            *guard += d;
        }
    }

    impl Default for FakeClock {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            *self.current.lock().expect("fake clock mutex poisoned")
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::time::Duration;

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
            let a = clock.now();
            let b = clock.now();
            assert_eq!(a, b);
        }
    }
}
