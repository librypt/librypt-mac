/// A Message Authentication Code (MAC) represented by a fixed array of bytes.
pub type Mac<const SIZE: usize> = [u8; SIZE];

/// A function for computing a MAC given a message and a `Secret`.
///
/// NOTE: Make sure to consult documentation for specific MAC algorithms, as some may require providing more data than what the compute functions require to be secure.
pub trait MacFn<const OUTPUT_SIZE: usize> {
    /// Compute a MAC given a message and a secret.
    fn compute(msg: &[u8], secret: &[u8]) -> Mac<OUTPUT_SIZE>;
}
