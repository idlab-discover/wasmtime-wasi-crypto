use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Limits(pub HashMap<&'static str, usize>);

impl Limits {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, algorithm: &'static str, limit: usize) {
        self.0.insert(algorithm, limit);
    }

    pub fn get(&self, algorithm: &'static str) -> Option<usize> {
        self.0.get(algorithm).copied()
    }
}
