/// A Message Authentication Code (MAC) represented by a fixed array of bytes.
pub type Mac<const SIZE: usize> = [u8; SIZE];

/// A function for computing a MAC given a message and a `Secret`.
///
/// NOTE: Make sure to consult documentation for specific MAC algorithms, as some may require providing more data than what the compute functions require to be secure.
pub trait MacFn<const OUTPUT_SIZE: usize>: Sized {
    /// Initialize MAC state.
    fn new(secret: &[u8]) -> Self;

    /// Update the MAC state with the given data.
    fn update(&mut self, data: &[u8]);

    /// Consumes the MAC state, producing the final MAC.
    fn finalize(self) -> Mac<OUTPUT_SIZE>;

    /// Produces the final MAC, resetting the MAC state for reuse.
    fn finalize_reset(&mut self) -> Mac<OUTPUT_SIZE>;

    /// Compute a MAC given a secret and a message.
    fn mac(secret: &[u8], message: &[u8]) -> Mac<OUTPUT_SIZE> {
        let mut mac = Self::new(secret);

        mac.update(message);

        mac.finalize()
    }
}
