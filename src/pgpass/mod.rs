//! Access Postgres credentials stored in the pgpass format.
//! <https://www.postgresql.org/docs/current/libpq-pgpass.html>
//!
//! The main functionality is documented in [`PgPass`].

// You might wonder why this is a seperate module when this could all be in the
// source root. This is a forwards-compatability strategy; it allows us to implement
// other formats (such as the connection service file) without reorganizing the project,
// which would result in a breaking change.

mod parser;
pub mod pattern;

use log::{debug, error, trace, warn};
use serde::{Deserialize, Serialize};
use std::{
    env,
    fs::File,
    io::{self, Read, Write},
    marker::PhantomData,
    path::{Path, PathBuf},
    str::{self, FromStr},
};
use thiserror::Error;

use crate::Credentials;

pub use self::parser::field::FieldError;
pub use self::parser::port::PortError;
pub use self::parser::ParsingError;
pub use self::pattern::{CredentialPattern, CredentialQuery};
use self::pattern::{HasPasswordTrue, InvalidField};

// Constants copied from Postgres documentation
pub const FILENAME: &str = ".pgpass";
pub const FILENAME_WINDOWS: &str = "pgpass.conf";
pub const PATH_ENVIRONMENT_VAR: &str = "PGPASSFILE";
pub const DELIMITER: &str = ":";
pub const DELIMITER_CHAR: char = ':';
pub const COMMENT: &str = "#";
pub const COMMENT_CHAR: char = '#';
pub const ESCAPE: &str = "\\";
pub const ESCAPE_CHAR: char = '\\';
pub const WILDCARD: &str = "*";
pub const WILDCARD_CHAR: char = '*';
pub const ESCAPABLE: [char; 3] = [ESCAPE_CHAR, WILDCARD_CHAR, DELIMITER_CHAR];

/// A set of Postgres credentials that can be queried with a simple pattern-matching
/// scheme.
/// <https://www.postgresql.org/docs/current/libpq-pgpass.html>
///
/// The [`PgPass`] contains a list of [`CredentialPattern`]s, which which contain passwords.
/// It provides an interface to look up credentials based on less-sensitive information
/// (such as a hostname). This allows tools to accept command line arguments indicating which
/// database they'd like to connect to, without exposing passwords on the command line.
///
/// ```
/// # use postgres_secrets::PgPass;
/// # use postgres_secrets::doctest_utils::fake_postgres as postgres;
/// # fn main() -> anyhow::Result<()> {
/// # let tls = ();
/// let s = "example.com:*:my_database:username:password";
/// let pgpass: PgPass = s.parse()?;
/// let creds = pgpass.query()
///     .hostname("example.com")?
///     .find()?
///     .unwrap();
/// let config: postgres::Config = creds.into();
/// let db = config.connect(tls);
/// # Ok(())
/// # }
/// ```
///
/// Use [`load`][PgPass::load] to automatically locate & read the file from it's
/// standard location.
///
/// # Format
///
/// pgpass credentials are stored in a colon-delimited flat file with the following
/// format:
///
/// `hostname:port:database:username:password`
///
/// Credentials are evaluated in order, meaning earlier entries have higher precedences.
///
/// For example:
///
/// `example.com:5432:my_database:webapp_user:secret`
///
/// ## Wildcards
///
/// Wild cards may be specified using `*`. A wildcard will match any input.
///
/// The password field is required. You may not put a wildcard in the password field.
///
/// For example, this line will match any database:
///
/// `example.com:5432:*:webapp_user:secret`
///
/// ## Escaping
///
/// `\` may be used to escape characters. Valid escape sequences are:
/// - `\\`
/// - `\:`
/// - `\*`
///
/// All others are considered invalid.
///
/// ## Comments
///
/// Any lines starting with `#` will be considered a comment and ignored.
///
/// # Querying
///
/// In order to obtain [`Credentials`], you need to [query][CredentialQuery]
/// for [patterns][CredentialPattern] using the methods [`find`][PgPass::find]
/// or [`query`][PgPass::query].
///
/// If the pattern contains wildcards, values from the query will be substituted.
/// If neither the pattern nor the query have a value for a given field, an
/// [`IncompleteCredential`] error will be returned. The exception is the port
/// field, which will be substituted for the [default port][super::DEFAULT_PORT].
///
/// # Caveats
/// - This does not behave precisely the same as the parser in `libpq`.
///     While unlikely, this could lead to bugs or confusing behavior
///     in some circumstances.
/// - `libpq` is more permissive than this implementation. `libpq` will
///     tolerate invalid escape sequences and extra columns. Because
///     this behavior could cause bugs and confusing behavior, this
///     implementation returns errors in these circumstances.
/// - `libpq` has special behavior when `localhost` is supplied as the
///     hostname. This library does not support this.
/// - `libpq` performs a permissions check on the pgpass file, and will
///     not open a file which is too permissive. This library does not
///     perform this check.
///
#[derive(Default, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PgPass {
    patterns: Vec<CredentialPattern<HasPasswordTrue>>,
}

impl PgPass {
    /// Automatically locate and load the pgpass file.
    /// See [`locate`][PgPass::locate] for more.
    pub fn load() -> Result<Self, LoadError> {
        let Some(path) = Self::locate() else {
            return Err(LoadError::CouldNotLocate);
        };
        Self::open(path)
    }
    /// Load credentials from the given file.
    pub fn read<F: Read>(mut f: F) -> Result<Self, LoadError> {
        let mut contents = Vec::with_capacity(8192);
        f.read_to_end(&mut contents)?;
        let s = str::from_utf8(&contents)?;

        Ok(parser::pgpass(s)?)
    }
    /// Load credentials from the file at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, LoadError> {
        let f = File::open(path.as_ref())?;
        Self::read(f)
    }
    /// Automatically locate the pgpass file. If the `PGPASSFILE` environment variable
    /// is set, then it's value will be used. Otherwise, `~/.pgpass` will be used on
    /// Unix systems, and `%APPDATA%\postgresql\pgpass.conf` on Windows.
    ///
    /// This behavior is specified in the
    /// [pgpass documentation](https://www.postgresql.org/docs/current/libpq-pgpass.html).
    pub fn locate() -> Option<PathBuf> {
        if let Some(path) = env::var_os(PATH_ENVIRONMENT_VAR).map(PathBuf::from) {
            trace!(
                "Using pgpass file from environment variable: {:?}",
                &path.as_os_str()
            );
            return Some(path);
        } else {
            debug!("Did not find PGPASSFILE envrironment variable")
        }
        #[cfg(unix)]
        {
            if let Some(home) = home::home_dir() {
                let path = home.join(FILENAME);
                if path.is_file() {
                    trace!("Using pgpass file from home: {:?}", &path.as_os_str());
                    return Some(path);
                } else {
                    debug!("~/.pgpass did not exist or was not a file")
                }
            } else {
                warn!("Failed to find home directory")
            }
        }
        #[cfg(windows)]
        {
            if let Some(app_data) = env::var_os("APPDATA").map(PathBuf::from) {
                let path = app_data.join(FILENAME_WINDOWS);
                if path.is_file() {
                    trace!("Using pgpass file from appdata: {:?}", &path.as_os_str());
                    return Some(path);
                } else {
                    debug!("%APPDATA%\\postgresql\\pgpass.conf did not exist or was not a file")
                }
            } else {
                warn!("Failed to find app data directory")
            }
        }

        error!("Failed to locate pgpass file");
        None
    }
    /// Write the patterns to a file.
    pub fn save_into<F: Write>(&self, f: &mut F) -> Result<(), io::Error> {
        let mut iterator = self.patterns.iter();
        let first = iterator.next();
        let capacity = first
            .as_ref()
            .map(|cred| cred.capacity_needed())
            .unwrap_or_default();
        let mut s = String::with_capacity(capacity);

        for cred in first.into_iter().chain(iterator) {
            cred.encode_into(&mut s);
            f.write(s.as_bytes())?;
            s.clear();
        }
        Ok(())
    }
    /// Save the credentials to a file at the given path. The file is opened
    /// with [`File::create_new`][a], so it must not already exist.
    ///
    /// [a]: std::fs::File::create_new
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), io::Error> {
        let mut f = File::create_new(path.as_ref())?;
        self.save_into(&mut f)
    }

    /// Add a pattern to the file. Patterns are evaluated in order, so this new
    /// pattern will have the lowest precedence.
    pub fn add(&mut self, cred: CredentialPattern<HasPasswordTrue>) {
        self.patterns.push(cred)
    }
    /// Builder interface to [`add`][a].
    ///
    /// [a]: PgPass::add
    pub fn with(mut self, cred: CredentialPattern<HasPasswordTrue>) -> Self {
        self.add(cred);
        self
    }
    /// Remove all patterns.
    pub fn clear(&mut self) {
        self.patterns.clear()
    }

    fn pattern_to_creds(
        query: &CredentialQuery,
        pattern: &CredentialPattern<HasPasswordTrue>,
    ) -> Result<Credentials, IncompleteCredential> {
        CredentialPattern::<HasPasswordTrue> {
            hostname: query
                .hostname
                .as_ref()
                .or(pattern.hostname.as_ref())
                .cloned(),
            port: query.port.or(pattern.port),
            database: query
                .database
                .as_ref()
                .or(pattern.database.as_ref())
                .cloned(),
            username: query
                .username
                .as_ref()
                .or(pattern.username.as_ref())
                .cloned(),
            password: pattern.password.clone(),
            _tag: PhantomData,
        }
        .try_into()
    }
    /// Returns the first set of credentials matching the query (if one exists).
    /// Any wildcard fields in the credential pattern will be populated from the
    /// query. If no port is supplied, the default port (5432) will be used. If
    /// any other fields are missing, an error will be returned. See [`query`][a]
    /// for a more ergonomic interface.
    ///
    /// ```
    /// # use postgres_secrets::pgpass::*;
    /// # fn main() -> anyhow::Result<()> {
    /// # let expected =  CredentialPattern::default()
    /// #   .hostname("localhost")?
    /// #   .port(123)?
    /// #   .database("my_database")?
    /// #   .username("username")?
    /// #   .password("password")?;
    /// # let pgpass = PgPass::default().with(expected.clone());
    /// # let actual =
    /// pgpass.find(
    ///     &CredentialQuery::default().username("username")?
    /// )?;
    /// # assert_eq!(expected, actual.unwrap());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [a]: PgPass::query
    pub fn find(
        &self,
        query: &CredentialQuery,
    ) -> Result<Option<Credentials>, IncompleteCredential> {
        for pattern in self.patterns.iter() {
            if let Some((query_hostname, pattern_hostname)) =
                query.hostname.as_ref().zip(pattern.hostname.as_ref())
            {
                if query_hostname != pattern_hostname {
                    continue;
                }
            }
            if let Some((query_port, pattern_port)) = query.port.zip(pattern.port) {
                if query_port != pattern_port {
                    continue;
                }
            }
            if let Some((query_database, pattern_database)) =
                query.database.as_ref().zip(pattern.database.as_ref())
            {
                if query_database != pattern_database {
                    continue;
                }
            }
            if let Some((query_username, pattern_username)) =
                query.username.as_ref().zip(pattern.username.as_ref())
            {
                if query_username != pattern_username {
                    continue;
                }
            }

            return Ok(Some(Self::pattern_to_creds(query, pattern)?));
        }

        Ok(None)
    }
    /// A more ergonomic interface to [`find`][a], allowing you to construct queries
    /// with a builder pattern.
    ///
    /// ```
    /// # use postgres_secrets::pgpass::*;
    /// # fn main() -> anyhow::Result<()> {
    /// # let expected =  CredentialPattern::default()
    /// #   .hostname("localhost")?
    /// #   .port(123)?
    /// #   .database("my_database")?
    /// #   .username("username")?
    /// #   .password("password")?;
    /// # let pgpass = PgPass::default().with(expected.clone());
    /// # let actual =
    /// pgpass.query()
    ///     .username("username")?
    ///     .find()?;
    /// # assert_eq!(expected, actual.unwrap());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [a]: PgPass::find
    pub fn query(&self) -> QueryBuilder<'_> {
        QueryBuilder {
            query: Default::default(),
            pgpass: self,
        }
    }
}
impl FromStr for PgPass {
    type Err = ParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parser::pgpass(s)
    }
}

/// A more ergonomic interface to [`PgPass::find`]. See [`PgPass::query`].
#[derive(Debug, Clone)]
pub struct QueryBuilder<'a> {
    query: CredentialQuery,
    pgpass: &'a PgPass,
}
impl QueryBuilder<'_> {
    pub fn find(self) -> Result<Option<Credentials>, IncompleteCredential> {
        self.pgpass.find(&self.query)
    }
    pub fn build(self) -> CredentialQuery {
        self.query
    }
    pub fn hostname<T: ToString>(mut self, hostname: T) -> Result<Self, InvalidField> {
        self.query = self.query.hostname(hostname)?;
        Ok(self)
    }
    pub fn port(mut self, port: u16) -> Result<Self, InvalidField> {
        self.query = self.query.port(port)?;
        Ok(self)
    }
    pub fn database<T: ToString>(mut self, database: T) -> Result<Self, InvalidField> {
        self.query = self.query.database(database)?;
        Ok(self)
    }
    pub fn username<T: ToString>(mut self, username: T) -> Result<Self, InvalidField> {
        self.query = self.query.username(username)?;
        Ok(self)
    }
}

/// An error encountered while reading a pgpass file.
#[derive(Error, Debug)]
pub enum LoadError {
    /// The pgpass file was invalid. It is safe to log or display this error;
    /// it will not contains passwords. (Broken escape sequences are displayed,
    /// so it is possible to leak up to two characters of a password.)
    #[error("{0}")]
    SyntaxError(#[from] ParsingError),
    /// We did not succeed in locating the pgpass file automatically.
    #[error("Unable to locate the pgpass file.")]
    CouldNotLocate,
    /// We encountered an I/O error while processing the file.
    #[error("{0}")]
    Io(#[from] io::Error),
    /// The file did not contain valid UTF8.
    #[error("{0}")]
    Utf8(#[from] str::Utf8Error),
}

/// An error encountered while querying [`PgPass`] for [credentials][Credentials].
/// This indicates that, while a pattern did match our query, we were missing
/// a required value.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IncompleteCredential {
    #[error("No hostname was supplied.")]
    MissingHostname,
    #[error("No database was supplied.")]
    MissingDatabase,
    #[error("No username was supplied.")]
    MissingUsername,
}

#[cfg(test)]
mod tests {
    use crate::DEFAULT_PORT;
    use std::io::{Cursor, Seek};

    use super::*;

    #[test]
    fn simple_find() -> anyhow::Result<()> {
        let expected = CredentialPattern::default()
            .hostname("localhost")?
            .port(123)?
            .database("database")?
            .username("username")?
            .password("password")?;
        let pgpass = PgPass::default().with(expected.clone());

        let actual = pgpass
            .find(&CredentialQuery::default().hostname("localhost").unwrap())?
            .unwrap();
        assert_eq!(expected, actual);

        let actual = pgpass
            .find(
                &CredentialQuery::default()
                    .hostname("does_not_exist")
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(None, actual);

        let actual = pgpass
            .find(&CredentialQuery::default().port(123).unwrap())?
            .unwrap();
        assert_eq!(expected, actual);

        let actual = pgpass.find(&CredentialQuery::default().port(65535).unwrap())?;
        assert_eq!(None, actual);

        let actual = pgpass
            .find(&CredentialQuery::default().database("database").unwrap())?
            .unwrap();
        assert_eq!(expected, actual);

        let actual = pgpass.find(
            &CredentialQuery::default()
                .database("does_not_exist")
                .unwrap(),
        )?;
        assert_eq!(None, actual);

        let actual = pgpass
            .find(&CredentialQuery::default().username("username").unwrap())?
            .unwrap();
        assert_eq!(expected, actual);

        let actual = pgpass
            .find(
                &CredentialQuery::default()
                    .username("does_not_exist")
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(None, actual);

        Ok(())
    }

    #[test]
    fn simple_query() -> anyhow::Result<()> {
        let expected = CredentialPattern::default()
            .hostname("localhost")?
            .port(123)?
            .database("database")?
            .username("username")?
            .password("password")?;
        let pgpass = PgPass::default().with(expected.clone());

        let actual = pgpass.query().hostname("localhost")?.find()?.unwrap();
        assert_eq!(expected, actual);

        let actual = pgpass.query().hostname("does_not_exist")?.find()?;
        assert_eq!(None, actual);

        let actual = pgpass.query().port(123)?.find()?.unwrap();
        assert_eq!(expected, actual);

        let actual = pgpass.query().port(65535)?.find()?;
        assert_eq!(None, actual);

        let actual = pgpass.query().database("database")?.find()?.unwrap();
        assert_eq!(expected, actual);

        let actual = pgpass.query().database("does_not_exist")?.find()?;
        assert_eq!(None, actual);

        let actual = pgpass.query().username("username")?.find()?.unwrap();
        assert_eq!(expected, actual);

        let actual = pgpass.query().username("does_not_exist")?.find()?;
        assert_eq!(None, actual);

        Ok(())
    }

    #[test]
    fn many_creds() -> anyhow::Result<()> {
        let a = CredentialPattern::default()
            .hostname("localhost")?
            .port(123)?
            .database("database")?
            .username("a")?
            .password("password")?;
        let b = CredentialPattern::default()
            .hostname("localhost")?
            .port(123)?
            .database("database")?
            .username("b")?
            .password("password")?;
        let c = CredentialPattern::default()
            .hostname("localhost")?
            .port(123)?
            .database("database")?
            .username("c")?
            .password("password")?;
        let pgpass = PgPass::default()
            .with(a.clone())
            .with(b.clone())
            .with(c.clone());

        /*
        let actual = pgpass.query().username("a")?.find()?.unwrap();
        assert_eq!(a, actual);

        let actual = pgpass.query().username("b")?.find()?.unwrap();
        assert_eq!(b, actual);

        let actual = pgpass.query().username("c")?.find()?.unwrap();
        assert_eq!(c, actual);
        */

        let actual = pgpass.query().username("does_not_exist")?.find()?;
        assert_eq!(None, actual);

        Ok(())
    }

    #[test]
    fn wildcard() -> anyhow::Result<()> {
        let a = CredentialPattern::default()
            .hostname("localhost")?
            .port(123)?
            .username("username")?
            .password("password")?;
        let expected = a.clone().database("database")?;
        let pgpass = PgPass::default().with(a);

        let actual = pgpass
            .query()
            .database("database")?
            .username("username")?
            .find()?
            .unwrap();
        assert_eq!(expected, actual);

        let actual = pgpass.query().database("database")?.find()?.unwrap();
        assert_eq!(expected, actual);

        Ok(())
    }

    #[test]
    fn wildcard_many_creds() -> anyhow::Result<()> {
        let a = CredentialPattern::default()
            .hostname("localhost")?
            .port(123)?
            .database("database1")?
            .username("one")?
            .password("password")?;
        let b = CredentialPattern::default()
            .hostname("localhost")?
            .port(123)?
            .database("database2")?
            .username("one")?
            .password("password")?;
        let c = CredentialPattern::default()
            .hostname("localhost")?
            .port(123)?
            .database("database3")?
            .username("two")?
            .password("password")?;
        let pgpass = PgPass::default()
            .with(a.clone())
            .with(b.clone())
            .with(c.clone());

        // a has the highest precedence
        let actual = pgpass.find(&Default::default())?.unwrap();
        assert_eq!(a, actual);

        let actual = pgpass.query().username("one")?.find()?.unwrap();
        assert_eq!(a, actual);

        let actual = pgpass.query().database("database2")?.find()?.unwrap();
        assert_eq!(b, actual);

        let actual = pgpass
            .query()
            .username("one")?
            .database("database2")?
            .find()?
            .unwrap();
        assert_eq!(b, actual);

        let actual = pgpass
            .query()
            .username("one")?
            .database("database3")?
            .find()?;
        assert_eq!(None, actual);

        Ok(())
    }

    #[test]
    fn missing() -> anyhow::Result<()> {
        let a = CredentialPattern::default()
            .port(65535)?
            .database("database")?
            .username("username")?
            .password("password_a")?;
        let b = CredentialPattern::default()
            .hostname("localhost")?
            .database("other_database")?
            .username("username")?
            .password("password_b")?;
        let c = CredentialPattern::default()
            .hostname("localhost")?
            .port(123)?
            .username("other_username")?
            .password("password_c")?;
        let d = CredentialPattern::default()
            .hostname("other_hostname")?
            .port(123)?
            .database("database")?
            .password("password_d")?;
        let pgpass = PgPass::default()
            .with(a.clone())
            .with(b.clone())
            .with(c.clone())
            .with(d.clone());

        let actual = pgpass.query().port(65535)?.find();
        assert_eq!(Err(IncompleteCredential::MissingHostname), actual);

        let expected = a.clone().hostname("this_hostname")?;
        let actual = pgpass
            .query()
            .hostname("this_hostname")?
            .port(65535)?
            .find()?
            .unwrap();
        assert_eq!(expected, actual);

        // The port is allowed to be missing.
        let expected = b.clone().port(DEFAULT_PORT)?;
        let actual = pgpass.query().database("other_database")?.find()?.unwrap();
        assert_eq!(expected, actual);

        let actual = pgpass.query().username("other_username")?.find();
        assert_eq!(Err(IncompleteCredential::MissingDatabase), actual);

        let expected = c.clone().database("this_database")?;
        let actual = pgpass
            .query()
            .username("other_username")?
            .database("this_database")?
            .find()?
            .unwrap();
        assert_eq!(expected, actual);

        let actual = pgpass.query().hostname("other_hostname")?.port(123)?.find();
        assert_eq!(Err(IncompleteCredential::MissingUsername), actual);

        let expected = d.clone().username("this_username")?;
        let actual = pgpass
            .query()
            .hostname("other_hostname")?
            .port(123)?
            .username("this_username")?
            .find()?
            .unwrap();
        assert_eq!(expected, actual);

        Ok(())
    }

    #[test]
    fn characters_are_escaped() -> anyhow::Result<()> {
        let pgpass = PgPass::default().with(
            CredentialPattern::default()
                .hostname("localhost")?
                .port(123)?
                .database("database")?
                .username("username")?
                .password("foo:bar")?,
        );

        let mut f: Cursor<Vec<u8>> = Default::default();
        pgpass.save_into(&mut f).unwrap();

        f.rewind().unwrap();
        let pgpass2 = PgPass::read(&mut f).unwrap();

        assert_eq!(pgpass, pgpass2);

        Ok(())
    }

    #[test]
    fn unrecognized_column() {
        let actual = "one:2:three:four:five:six".parse::<PgPass>().err();
        assert_eq!(actual, Some(ParsingError::UnrecognizedColumn));
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    use std::{
        io::{Cursor, Seek},
        num::NonZeroU16,
    };
    const VALID_FIELD: &str = "[^\r\n#]+";
    const ARBITRARY_FIELD: &str = ".+";

    proptest! {
        #[test]
        fn all_valid_files_are_accepted(
            patterns in prop::collection::vec((
                VALID_FIELD,
                1..65535u16,
                VALID_FIELD,
                VALID_FIELD,
                VALID_FIELD
            ), 1..10))
        {
            let pgpass = PgPass {
                patterns: patterns.into_iter()
                    .map(|(hostname, port, database, username, password)| {
                        CredentialPattern::default()
                            .hostname(hostname).unwrap()
                            .port(port).unwrap()
                            .database(database).unwrap()
                            .username(username).unwrap()
                            .password(password).unwrap()
                    }).collect(),
            };

            let mut f: Cursor<Vec<u8>> = Default::default();
            pgpass.save_into(&mut f).unwrap();

            f.rewind().unwrap();
            let pgpass2 = PgPass::read(&mut f).unwrap();

            assert_eq!(pgpass, pgpass2)
        }

        #[test]
        fn no_unknown_parsing_errors_on_invalid_inputs(
            patterns in prop::collection::vec((
                ARBITRARY_FIELD,
                1..65535u16,
                ARBITRARY_FIELD,
                ARBITRARY_FIELD,
                ARBITRARY_FIELD
            ), 1..10))
        {
            // Test against invalid files that are structured correctly but contain
            // illegal characters

            let pgpass = PgPass {
                patterns: patterns.into_iter()
                    .map(|(hostname, port, database, username, password)| {
                        // Construct the pattern directly to bypass validation
                        CredentialPattern {
                            hostname: Some(hostname.to_string()),
                            port: Some(NonZeroU16::new(port).unwrap()),
                            database: Some(database.to_string()),
                            username: Some(username.to_string()),
                            password: password.to_string(),
                            _tag: PhantomData
                    }
                    }).collect(),
            };

            let mut f: Cursor<Vec<u8>> = Default::default();
            pgpass.save_into(&mut f).unwrap();

            f.rewind().unwrap();
            match PgPass::read(&mut f)  {
                Err(LoadError::SyntaxError(e)) => {
                    match e {
                        ParsingError::InvalidHostname(FieldError::Unknown(_))
                        | ParsingError::InvalidPort(PortError::Unknown(_))
                        | ParsingError::InvalidDatabase(FieldError::Unknown(_))
                        | ParsingError::InvalidUsername(FieldError::Unknown(_))
                        | ParsingError::InvalidPassword(FieldError::Unknown(_))
                        | ParsingError::Unknown(_) => panic!("Unknown error detected"),
                        _ => ()
                    }
                }
                _ => ()
            }
        }

        #[test]
        fn no_unknown_parsing_errors_on_trash(input in ".*") {
            // Test against completely arbitrary files

            match input.parse::<PgPass>() {
                Err(e) => match e {
                    ParsingError::InvalidHostname(FieldError::Unknown(_))
                    | ParsingError::InvalidPort(PortError::Unknown(_))
                    | ParsingError::InvalidDatabase(FieldError::Unknown(_))
                    | ParsingError::InvalidUsername(FieldError::Unknown(_))
                    | ParsingError::InvalidPassword(FieldError::Unknown(_))
                    | ParsingError::Unknown(_) => panic!("Unknown error detected"),
                    _ => ()
                }
                _ => ()
            }
        }
    }
}
