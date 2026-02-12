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
