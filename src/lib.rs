use std::error::Error;

/// Represents a Message Authentication Code that can be attached to a message.
pub type Mac<const LENGTH: usize> = [u8; LENGTH];

/// Represents an algorithm for computing a MAC given a message and a `Secret`.
///
/// NOTE: Make sure to consult documentation for specific MAC algorithms, as some may require providing more data than what the compute functions require to be secure.
pub trait MacAlgorithm<const LENGTH: usize> {
    type MacError: Error;

    /// Attempt to compute a MAC given a message and a secret.
    fn try_compute(&self, msg: &[u8], secret: &[u8]) -> Result<Mac<LENGTH>, Self::MacError>;

    /// Compute a MAC given a message and a secret.
    ///
    /// NOTE: This function will panic if the computation fails. See `try_compute` for a version with error handling.
    fn compute(&self, msg: &[u8], secret: &[u8]) -> Mac<LENGTH> {
        self.try_compute(msg, secret).unwrap()
    }
}
