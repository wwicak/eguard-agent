#[derive(Debug, Clone, Default)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        let len = self.0.len();
        self.0.clear();
        if self.0.capacity() < len {
            self.0.shrink_to(len);
        }
    }
}
