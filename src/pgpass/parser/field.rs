use nom::{
    branch::alt,
    bytes::complete::{escaped_transform, tag},
    character::complete::none_of,
    combinator::value,
    error::{ErrorKind, ParseError},
    Err as NomErr, IResult, Parser,
};

use crate::pgpass::{DELIMITER, ESCAPE, ESCAPE_CHAR, WILDCARD};

pub fn wildcard(s: &str) -> IResult<&str, ()> {
    let (remaining, _) = tag(WILDCARD).parse(s)?;
    Ok((remaining, ()))
}

pub fn field_value(s: &str) -> IResult<&str, String, FieldError> {
    if s.is_empty() || s.starts_with(DELIMITER) {
        return Err(NomErr::Error(FieldError::Empty));
    };

    escaped_transform(
        none_of("\\:*\r\n"),
        ESCAPE_CHAR,
        alt((
            value(ESCAPE, tag(ESCAPE)),
            value(DELIMITER, tag(DELIMITER)),
            value(WILDCARD, tag(WILDCARD)),
        )),
    )
    .parse(s)
}

pub fn field(s: &str) -> IResult<&str, Option<String>, FieldError> {
    if let Ok((remaining, _)) = wildcard.parse(s) {
        Ok((remaining, None))
    } else {
        let (remaining, x) = field_value.parse(s)?;
        Ok((remaining, Some(x)))
    }
}

pub fn required_field(s: &str) -> IResult<&str, String, FieldError> {
    if let Ok((_remaining, _)) = wildcard.parse(s) {
        return Err(NomErr::Error(FieldError::Required));
    }
    field_value.parse(s)
}

/// An error encountered when parsing an invalid hostname, database,
/// username, or password field in a pgpass file.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum FieldError {
    /// The supplied value was empty. This is invalid; use the wildcard character `*`.
    #[error("Fields must not be empty (use * for wildcards).")]
    Empty,
    /// The escape sequence was invalid. The only valid escape sequences are `\*`,
    /// `\:`, and `\\`.
    #[error("Invalid escape sequence: '\\{0}' is not a valid escape sequence.")]
    InvalidEscape(char),
    /// An escape character was found, but with no character after it.
    #[error("Invalid escape sequence: No character supplied")]
    InvalidEscapeNoChar,
    /// A required field was omitted. (`password` is the only required field.)
    #[error("This field is required.")]
    Required,
    /// The field was not followed by it's delimiter
    #[error("The delimiter character was not found")]
    Undelimited,
    /// An unanticipated error from `nom`. This should not happen. If you observe
    /// this error, it is a bug.
    #[error("An unknown error occurred during parsing (kind: {0:?}).")]
    Unknown(ErrorKind),
}
impl ParseError<&str> for FieldError {
    fn from_error_kind(_input: &str, kind: ErrorKind) -> Self {
        // We do NOT store the input. Otherwise, we may accidentally expose
        // passwords in logs.
        if kind == ErrorKind::EscapedTransform {
            Self::InvalidEscapeNoChar
        } else {
            Self::Unknown(kind)
        }
    }

    fn append(input: &str, kind: ErrorKind, other: Self) -> Self {
        if kind == ErrorKind::Alt {
            if input.is_empty() {
                Self::InvalidEscapeNoChar
            } else {
                Self::InvalidEscape(input.chars().next().unwrap())
            }
        } else {
            other
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn simple_wildcard() {
        let s = "*abc";
        assert_eq!(wildcard.parse(s).unwrap(), ("abc", ()));

        let s = "abc";
        assert!(wildcard.parse(s).is_err());
    }

    #[test]
    fn simple_field() {
        let s = "abc:def";
        let expected = (":def", Some("abc".to_string()));
        assert_eq!(field.parse(s).unwrap(), expected);
    }

    #[test]
    fn simple_required_field() {
        let s = "abc:def";
        let expected = (":def", "abc".to_string());
        assert_eq!(required_field.parse(s).unwrap(), expected);
    }

    #[test]
    fn wildcard_yields_none() {
        let s = "*:def";
        let expected = (":def", None);
        assert_eq!(field.parse(s).unwrap(), expected);
    }

    #[test]
    fn escape_delimiter() {
        let s = "abc\\::def";
        let expected = (":def", Some("abc:".to_string()));
        assert_eq!(field.parse(s).unwrap(), expected);
    }

    #[test]
    fn escape_wildcard() {
        let s = "abc\\*:def";
        let expected = (":def", Some("abc*".to_string()));
        assert_eq!(field.parse(s).unwrap(), expected);
    }

    #[test]
    fn escape_escape_char() {
        let s = "abc\\\\:def";
        let expected = (":def", Some("abc\\".to_string()));
        assert_eq!(field.parse(s).unwrap(), expected);
    }

    #[test]
    fn empty() {
        let s = ":def";
        let expected = FieldError::Empty;
        let NomErr::Error(actual) = field(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);

        let s = "";
        let expected = FieldError::Empty;
        let NomErr::Error(actual) = field(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn required_rejects_wildcard() {
        let s = "*:def";
        let expected = FieldError::Required;
        let NomErr::Error(actual) = required_field.parse(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn invalid_escape_char() {
        let s = "\\xabc";
        let expected = FieldError::InvalidEscape('x');
        let NomErr::Error(actual) = field(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);

        let s = "ab\\xc:";
        let expected = FieldError::InvalidEscape('x');
        let NomErr::Error(actual) = field(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);

        let s = "abc\\x:";
        let expected = FieldError::InvalidEscape('x');
        let NomErr::Error(actual) = field(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn invalid_escape_no_char() {
        let s = "abc\\";
        let expected = FieldError::InvalidEscapeNoChar;
        let NomErr::Error(actual) = field(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);
    }
}
