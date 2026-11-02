use crate::options::OptionsLike;
use std::any::Any;

/// Options for `secrets-manager.open`.
///
/// The WIT constructor is infallible, so the host must be able to push a real
/// resource even though no secrets manager is implemented. No option names are
/// recognised, so every setter keeps the `OptionsLike` default of returning
/// `UnsupportedOption`.
#[derive(Clone, Debug, Default)]
pub struct SecretsManagerOptions {}

impl OptionsLike for SecretsManagerOptions {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
