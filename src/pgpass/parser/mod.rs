use nom::{
    error::{ErrorKind, ParseError},
    Finish, Parser,
};

use crate::PgPass;

use self::{
    credential_pattern::credential_pattern, field::FieldError, ignored::ignored, port::PortError,
};

pub mod credential_pattern;
pub mod field;
pub mod ignored;
pub mod port;

pub fn pgpass(s: &str) -> Result<PgPass, ParsingError> {
    let mut patterns = Vec::with_capacity(8);
    let mut remaining = s;
    while !remaining.is_empty() {
        if let Ok((r, _)) = ignored.parse(remaining) {
            remaining = r;
        } else {
            let (r, pattern) = credential_pattern(remaining).finish()?;
            remaining = r;
            patterns.push(pattern);
        }
    }

    Ok(PgPass { patterns })
}

/// An error encountered when parsing an invalid pgpass file.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum ParsingError {
    #[error("Invalid hostname: {0}")]
    InvalidHostname(FieldError),
    #[error("Invalid port: {0}")]
    InvalidPort(#[from] PortError),
    #[error("Invalid database name: {0}")]
    InvalidDatabase(FieldError),
    #[error("Invalid username: {0}")]
    InvalidUsername(FieldError),
    #[error("Invalid password: {0}")]
    InvalidPassword(FieldError),
    #[error("Encountered a column after 'password'. This is invalid.")]
    UnrecognizedColumn,
    /// An unanticipated error from `nom`. This should not happen. If you observe
    /// this error, it is a bug.
    #[error("An unknown error occurred during parsing (kind: {0:?}).")]
    Unknown(ErrorKind),
}
impl ParseError<&str> for ParsingError {
    fn from_error_kind(_input: &str, kind: nom::error::ErrorKind) -> Self {
        // We do NOT store the input. Otherwise, we may accidentally expose
        // passwords in logs.
        Self::Unknown(kind)
    }

    fn append(_input: &str, _kind: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::pgpass::CredentialPattern;

    #[test]
    fn simple() -> anyhow::Result<()> {
        let s = "one:2:three:four:five";
        let expected = PgPass::default().with(
            CredentialPattern::default()
                .hostname("one")?
                .port(2)?
                .database("three")?
                .username("four")?
                .password("five")?,
        );
        let actual = pgpass(s).unwrap();
        assert_eq!(actual, expected);

        Ok(())
    }

    #[test]
    fn many() -> anyhow::Result<()> {
        let s = "one:2:three:four:five\na:1:b:c:d";
        let expected = PgPass::default()
            .with(
                CredentialPattern::default()
                    .hostname("one")?
                    .port(2)?
                    .database("three")?
                    .username("four")?
                    .password("five")?,
            )
            .with(
                CredentialPattern::default()
                    .hostname("a")?
                    .port(1)?
                    .database("b")?
                    .username("c")?
                    .password("d")?,
            );
        let actual = pgpass(s).unwrap();
        assert_eq!(actual, expected);

        Ok(())
    }

    #[test]
    fn either_linebreak_convention_works() {
        let s1 = "one:2:three:four:five\na:1:b:c:d";
        let s2 = "one:2:three:four:five\r\na:1:b:c:d";
        assert_eq!(pgpass(s1), pgpass(s2));
    }

    #[test]
    fn with_ignored() -> anyhow::Result<()> {
        let s = "one:2:three:four:five\n\na:1:b:c:d\n# Foo bar baz\r\n\r\n# Abc def";
        let expected = PgPass::default()
            .with(
                CredentialPattern::default()
                    .hostname("one")?
                    .port(2)?
                    .database("three")?
                    .username("four")?
                    .password("five")?,
            )
            .with(
                CredentialPattern::default()
                    .hostname("a")?
                    .port(1)?
                    .database("b")?
                    .username("c")?
                    .password("d")?,
            );
        let actual = pgpass(s).unwrap();
        assert_eq!(actual, expected);

        Ok(())
    }
}
