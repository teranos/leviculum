/// no_std-compatible hex formatter for tracing output.
pub(crate) struct HexFmt<'a>(pub &'a [u8]);

impl core::fmt::Display for HexFmt<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Short hex formatter: first 8 bytes (16 hex chars) for compact log lines.
///
/// Mirrors Python's `prettyhexrep` which truncates hashes for readability.
/// Use `HexFmt` for full hashes (warn!/error! where precision matters),
/// `HexShort` for debug!/trace! where brevity matters.
pub(crate) struct HexShort<'a>(pub &'a [u8]);

impl core::fmt::Display for HexShort<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let n = self.0.len().min(8);
        for b in &self.0[..n] {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}
