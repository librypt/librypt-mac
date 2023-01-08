/// Represents the raw bytes of a Message Authentication Code (MAC).
pub type Mac<const SIZE: usize> = [u8; SIZE];

/// Represents an algorithm for computing a MAC given a message and a `Secret`.
///
/// NOTE: Make sure to consult documentation for specific MAC algorithms, as some may require providing more data than what the compute functions require to be secure.
pub trait MacAlgorithm<const OUTPUT_SIZE: usize> {
    /// Initialize MAC state.
    fn new(secret: &[u8]) -> Self;

    /// Update the input state of the MAC with the provided data.
    fn update(&mut self, data: &[u8]);

    /// Compute the final MAC with the MAC state.
    fn finalize(self) -> Mac<OUTPUT_SIZE>;

    /// Compute the final MAC with the MAC state, clearing the state for reuse.
    fn finalize_reset(&mut self) -> Mac<OUTPUT_SIZE>;

    /// Compute a MAC given a message and a secret.
    fn compute(msg: &[u8], secret: &[u8]) -> Mac<OUTPUT_SIZE>;
}
