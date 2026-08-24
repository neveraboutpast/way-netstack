/// Minimum level of events the netstack emits. `None` silences everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub enum LogLevel {
    None,
    Error,
    Warning,
    Info,
    Debug,
}

impl LogLevel {
    /// Ordinal order so usefulness comparisons work. `None < Error < Warning < Info < Debug`.
    pub const fn ordinal(self) -> u8 {
        match self {
            LogLevel::None => 0,
            LogLevel::Error => 1,
            LogLevel::Warning => 2,
            LogLevel::Info => 3,
            LogLevel::Debug => 4,
        }
    }

    /// Whether `lvl` can pass a configured level of `self`.
    pub const fn includes(self, lvl: LogLevel) -> bool {
        self.ordinal() >= lvl.ordinal()
    }
}

/// Gated emit dispatcher. Internal: callers hold `core.config.log_level`.
///
/// Call sites gate the `tracing::*!` macros themselves (they carry the format
/// string and arguments), so this only answers the question "may `lvl` pass?".
pub(crate) fn enabled(configured: LogLevel, lvl: LogLevel) -> bool {
    configured.includes(lvl)
}
