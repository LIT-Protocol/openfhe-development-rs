macro_rules! hex_enum_usize {
    ($name:ident) => {
        impl std::fmt::LowerHex for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{:x}", *self as usize)
            }
        }

        impl std::fmt::UpperHex for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{:X}", *self as usize)
            }
        }
    };
}

macro_rules! serde_str_or_u8 {
    ($name:ident) => {
        impl serde::Serialize for $name {
            fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                if s.is_human_readable() {
                    s.serialize_str(&self.to_string())
                } else {
                    s.serialize_u8((*self as usize) as u8)
                }
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(d: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                if d.is_human_readable() {
                    let s = String::deserialize(d)?;
                    s.parse().map_err(serde::de::Error::custom)
                } else {
                    let u = u8::deserialize(d)?;
                    Ok($name::from(u as usize))
                }
            }
        }
    };
}

macro_rules! try_serde_str_or_u8 {
    ($name:ident) => {
        impl serde::Serialize for $name {
            fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                if s.is_human_readable() {
                    s.serialize_str(&self.to_string())
                } else {
                    s.serialize_u8((*self as usize) as u8)
                }
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(d: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                if d.is_human_readable() {
                    let s = String::deserialize(d)?;
                    s.parse().map_err(serde::de::Error::custom)
                } else {
                    let u = u8::deserialize(d)?;
                    Ok($name::try_from(u as usize).map_err(serde::de::Error::custom)?)
                }
            }
        }
    };
}
