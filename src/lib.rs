#![deny(unused_must_use)]
//! A secure way to access Postgres credentials from a file.
//!
//! `postgres_secrets` allows you to encode less-sensitive information about
//! a database, such as a hostname or database name, in insecure configuration
//! vectors such as command lines. The password can then be looked up using from
//! a file supplied via the user's dotfiles or systems like Docker secrets.
//!
//! Currently, only the [`pgpass`](https://www.postgresql.org/docs/current/libpq-pgpass.html)
//! format is supported. Support for [`connection service files`](https://www.postgresql.org/docs/current/libpq-pgservice.html)
//! may be implemented in the future.
//!
//! The main functionality is documented in [`PgPass`].

use std::{fmt::Debug, num::NonZeroU16};

use serde::{Deserialize, Serialize};

pub mod pgpass;
pub use pgpass::PgPass;
#[doc(hidden)]
pub mod doctest_utils;

pub const DEFAULT_PORT: u16 = 5432;

/// Credentials for accessing a Postgres database.
/// This can be used either by accessing it's fields directly, or by converting
/// it into a [`postgres::Config`].
///
/// ```
/// # use postgres_secrets::pgpass::*;
/// # use postgres_secrets::doctest_utils::fake_postgres as postgres;
/// #
/// # fn main() -> anyhow::Result<()> {
/// # let tls = ();
/// # let pgpass = PgPass::default().with(
/// #    CredentialPattern::default()
/// #    .hostname("localhost")?
/// #    .port(123)?
/// #    .database("my_database")?
/// #    .username("username")?
/// #    .password("password")?
/// # );
/// let creds = pgpass.query()
///     .username("username")?
///     .find()?
///     .unwrap();
/// let config: postgres::Config = creds.into();
/// let db = config.connect(tls)?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Credentials {
    pub hostname: String,
    pub port: NonZeroU16,
    pub database: String,
    pub username: String,
    pub password: String,
}
impl From<Credentials> for postgres::Config {
    fn from(value: Credentials) -> Self {
        let mut config = Self::new();
        config
            .host(&value.hostname)
            .port(value.port.get())
            .dbname(&value.database)
            .user(&value.username)
            .password(&value.password);
        config
    }
}
impl Debug for Credentials {
    // Hand-rolled to censor passwords
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("hostname", &self.hostname)
            .field("port", &self.port)
            .field("database", &self.database)
            .field("username", &self.username)
            .field("password", &"[ Censored ]")
            .finish()
    }
}
