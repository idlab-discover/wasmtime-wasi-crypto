#[cfg(feature = "pqcrypto")]
mod mlkem;
#[cfg(feature = "pqcrypto")]
mod xwing;

#[cfg(feature = "pqcrypto")]
pub use self::mlkem::MlKemKeyPairBuilder;
#[cfg(feature = "pqcrypto")]
pub use self::xwing::XWingKeyPairBuilder;

#[derive(Clone, Debug)]
pub struct EncapsulatedSecret {
    pub encapsulated_secret: Vec<u8>,
    pub secret: Vec<u8>,
}
