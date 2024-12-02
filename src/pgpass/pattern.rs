use serde::{Deserialize, Serialize};
use std::{marker::PhantomData, num::NonZeroU16};

use crate::{Credentials, DEFAULT_PORT};

use super::{
    IncompleteCredential, DELIMITER, DELIMITER_CHAR, ESCAPABLE, ESCAPE_CHAR, WILDCARD,
    WILDCARD_CHAR,
};

fn escape_into(s: &str, output: &mut String) {
    for c in s.chars() {
        if ESCAPABLE.contains(&c) {
            output.push(ESCAPE_CHAR);
        }
        output.push(c);
    }
}

fn valid_field(s: &str) -> Result<(), Invalidity> {
    if s.is_empty() {
        Err(Invalidity::Empty)
    } else if s.chars().any(|c| ['\n', '\r'].contains(&c)) {
        Err(Invalidity::ContainsLinebreak)
    } else {
        Ok(())
    }
}

/// Sentinel value which prevents a [`CredentialPattern`] to being added
/// to a [`PgPass`][super::PgPass] before [`CredentialPattern::password`]
/// is called.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HasPasswordFalse;

/// Sentinel value which allows a [`CredentialPattern`] to be added to
/// a [`PgPass`][super::PgPass].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HasPasswordTrue;

/// A row of a pgpass file. `None` values indicate a wildcard. The only
/// required field is `password`.
///
/// # Note
///
/// Password is a required field. If you are manually constructing a `CredentialPattern`,
/// you will need to call [`password`][`CredentialPattern::password`] before it can be
/// added to a [`PgPass`][super::PgPass].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CredentialPattern<HasPassword = HasPasswordFalse> {
    pub hostname: Option<String>,
    pub port: Option<NonZeroU16>,
    pub database: Option<String>,
    pub username: Option<String>,
    pub password: String,
    pub(crate) _tag: PhantomData<HasPassword>,
}
impl<HasPassword> CredentialPattern<HasPassword> {
    pub fn hostname<T: ToString>(self, hostname: T) -> Result<Self, InvalidField> {
        let s = hostname.to_string();
        if let Err(e) = valid_field(&s) {
            Err(InvalidField::InvalidHostname(e))
        } else {
            Ok(Self {
                hostname: Some(s),
                ..self
            })
        }
    }
    pub fn port(self, port: u16) -> Result<Self, InvalidField> {
        if let Some(port) = NonZeroU16::new(port) {
            Ok(Self {
                port: Some(port),
                ..self
            })
        } else {
            Err(InvalidField::InvalidPortNumber)
        }
    }
    pub fn database<T: ToString>(self, database: T) -> Result<Self, InvalidField> {
        let s = database.to_string();
        if let Err(e) = valid_field(&s) {
            Err(InvalidField::InvalidHostname(e))
        } else {
            Ok(Self {
                database: Some(s),
                ..self
            })
        }
    }
    pub fn username<T: ToString>(self, username: T) -> Result<Self, InvalidField> {
        let s = username.to_string();
        if let Err(e) = valid_field(&s) {
            Err(InvalidField::InvalidHostname(e))
        } else {
            Ok(Self {
                username: Some(s),
                ..self
            })
        }
    }
    pub(crate) fn capacity_needed(&self) -> usize {
        let hostname_cap = self
            .hostname
            .as_ref()
            .map(|s| s.len())
            .unwrap_or(WILDCARD.len())
            + DELIMITER.len();
        let port_cap = "65535".len() + DELIMITER.len();
        let database_cap = self
            .database
            .as_ref()
            .map(|s| s.len())
            .unwrap_or(WILDCARD.len())
            + DELIMITER.len();
        let username_cap = self
            .username
            .as_ref()
            .map(|s| s.len())
            .unwrap_or(WILDCARD.len());
        let password_cap = self.password.len() + "\n".len();

        hostname_cap + port_cap + database_cap + username_cap + password_cap
    }
}
impl CredentialPattern<HasPasswordFalse> {
    pub fn password<T: ToString>(
        self,
        password: T,
    ) -> Result<CredentialPattern<HasPasswordTrue>, InvalidField> {
        let s = password.to_string();
        if let Err(e) = valid_field(&s) {
            Err(InvalidField::InvalidHostname(e))
        } else {
            Ok(CredentialPattern::<HasPasswordTrue> {
                hostname: self.hostname,
                port: self.port,
                database: self.database,
                username: self.username,
                password: s,
                _tag: PhantomData,
            })
        }
    }
}
impl CredentialPattern<HasPasswordTrue> {
    pub fn password<T: ToString>(self, password: T) -> Result<Self, InvalidField> {
        let s = password.to_string();
        if let Err(e) = valid_field(&s) {
            Err(InvalidField::InvalidHostname(e))
        } else {
            Ok(Self {
                password: s,
                ..self
            })
        }
    }
    /// Encode the pattern into the pgpass format.
    pub fn encode(&self) -> String {
        let mut s = String::with_capacity(self.capacity_needed());
        self.encode_into(&mut s);
        s
    }
    /// Encode the pattern into the pgpass format, writing the result into the
    /// supplied string.
    pub fn encode_into(&self, output: &mut String) {
        if let Some(needed) = self.capacity_needed().checked_sub(output.capacity()) {
            output.reserve(needed);
        };
        for field in [
            self.hostname.as_ref(),
            self.port.map(|p| p.to_string()).as_ref(),
            self.database.as_ref(),
            self.username.as_ref(),
        ] {
            if let Some(field) = field {
                escape_into(field, output);
            } else {
                output.push(WILDCARD_CHAR);
            }
            output.push(DELIMITER_CHAR);
        }

        escape_into(&self.password, output);
        output.push('\n');
    }
    /// Returns True of the pattern contains no wildcards (except in the port field,
    /// as this field has a default value). If this function returns true, converting
    /// the pattern into a [`Credential`][a] will not return an error.
    ///
    /// [a]: crate::Credentials
    pub fn exact(&self) -> bool {
        self.hostname.is_some() && self.database.is_some() && self.username.is_some()
    }
}
impl Default for CredentialPattern<HasPasswordFalse> {
    fn default() -> Self {
        Self {
            hostname: Default::default(),
            port: Default::default(),
            database: Default::default(),
            username: Default::default(),
            password: Default::default(),
            _tag: PhantomData,
        }
    }
}
impl TryFrom<CredentialPattern<HasPasswordTrue>> for Credentials {
    type Error = IncompleteCredential;

    fn try_from(value: CredentialPattern<HasPasswordTrue>) -> Result<Self, Self::Error> {
        if value.hostname.is_none() {
            return Err(IncompleteCredential::MissingHostname);
        }
        if value.database.is_none() {
            return Err(IncompleteCredential::MissingDatabase);
        }
        if value.username.is_none() {
            return Err(IncompleteCredential::MissingUsername);
        }

        Ok(Self {
            hostname: value.hostname.unwrap(),
            port: value.port.unwrap_or(NonZeroU16::new(DEFAULT_PORT).unwrap()),
            database: value.database.unwrap(),
            username: value.username.unwrap(),
            password: value.password,
        })
    }
}
impl<T> PartialEq<Credentials> for CredentialPattern<T> {
    fn eq(&self, other: &Credentials) -> bool {
        self.hostname.as_ref() == Some(&other.hostname)
            && self.port == Some(other.port)
            && self.database.as_ref() == Some(&other.database)
            && self.username.as_ref() == Some(&other.username)
            && self.password == other.password
    }
}

/// A query for looking up credentials from [`PgPass`][super::PgPass]. `None` values
/// indicate a wildcard.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CredentialQuery {
    pub hostname: Option<String>,
    pub port: Option<NonZeroU16>,
    pub database: Option<String>,
    pub username: Option<String>,
}
impl CredentialQuery {
    pub fn hostname<T: ToString>(self, hostname: T) -> Result<Self, InvalidField> {
        let s = hostname.to_string();
        if let Err(e) = valid_field(&s) {
            Err(InvalidField::InvalidHostname(e))
        } else {
            Ok(Self {
                hostname: Some(s),
                ..self
            })
        }
    }
    pub fn port(self, port: u16) -> Result<Self, InvalidField> {
        if let Some(port) = NonZeroU16::new(port) {
            Ok(Self {
                port: Some(port),
                ..self
            })
        } else {
            Err(InvalidField::InvalidPortNumber)
        }
    }
    pub fn database<T: ToString>(self, database: T) -> Result<Self, InvalidField> {
        let s = database.to_string();
        if let Err(e) = valid_field(&s) {
            Err(InvalidField::InvalidHostname(e))
        } else {
            Ok(Self {
                database: Some(s),
                ..self
            })
        }
    }
    pub fn username<T: ToString>(self, username: T) -> Result<Self, InvalidField> {
        let s = username.to_string();
        if let Err(e) = valid_field(&s) {
            Err(InvalidField::InvalidHostname(e))
        } else {
            Ok(Self {
                username: Some(s),
                ..self
            })
        }
    }
}

/// An error encountered when using an invalid value to build a
/// [`CredentialPattern`] or [`CredentialQuery`].
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum InvalidField {
    #[error("Invalid hostname: {0}")]
    InvalidHostname(Invalidity),
    #[error("Invalid port number: 0 is not a valid port number.")]
    InvalidPortNumber,
    #[error("Invalid database: {0}")]
    InvalidDatabase(Invalidity),
    #[error("Invalid username: {0}")]
    InvalidUsername(Invalidity),
    #[error("Invalid password: {0}")]
    InvalidPassword(Invalidity),
}

/// Enumerates the ways a field may be invalid.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Invalidity {
    #[error("Fields must not contain linebreaks.")]
    ContainsLinebreak,
    #[error("Fields must not be empty.")]
    Empty,
}
