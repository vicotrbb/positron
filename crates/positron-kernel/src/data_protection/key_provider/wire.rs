use serde::Deserialize;
use zeroize::Zeroizing;

// Serde borrows ordinary wire strings. Valid JSON escapes require an owned
// decoding buffer, which must have the same zeroizing lifetime as plaintext.
pub(super) enum SecretText<'a> {
    Borrowed(&'a str),
    Owned(Zeroizing<String>),
}
impl SecretText<'_> {
    pub(super) fn as_str(&self) -> &str {
        match self {
            Self::Borrowed(value) => value,
            Self::Owned(value) => value.as_str(),
        }
    }
}
impl<'de: 'a, 'a> Deserialize<'de> for SecretText<'a> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TextVisitor<'a>(std::marker::PhantomData<&'a str>);
        impl<'de: 'a, 'a> serde::de::Visitor<'de> for TextVisitor<'a> {
            type Value = SecretText<'a>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a bounded wire string")
            }
            fn visit_borrowed_str<E: serde::de::Error>(
                self,
                value: &'de str,
            ) -> Result<Self::Value, E> {
                Ok(SecretText::Borrowed(value))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(SecretText::Owned(Zeroizing::new(value.to_owned())))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(SecretText::Owned(Zeroizing::new(value)))
            }
        }
        deserializer.deserialize_str(TextVisitor(std::marker::PhantomData))
    }
}
