use std::sync::atomic::{AtomicU8, Ordering};

pub const OVERLOAD_NORMAL: u8 = 0;
pub const OVERLOAD_SHED_KEEPALIVE: u8 = 1;
pub const OVERLOAD_REJECT: u8 = 2;

#[derive(Debug, Default)]
pub struct OverloadState {
    level: AtomicU8,
}

impl OverloadState {
    pub fn new() -> Self {
        OverloadState::default()
    }

    pub fn level(&self) -> u8 {
        self.level.load(Ordering::Relaxed)
    }

    pub fn set_level(&self, level: u8) {
        self.level.store(level, Ordering::Relaxed);
    }

    pub fn sheds_keepalive(&self) -> bool {
        self.level() >= OVERLOAD_SHED_KEEPALIVE
    }

    pub fn rejects_new_work(&self) -> bool {
        self.level() >= OVERLOAD_REJECT
    }
}
