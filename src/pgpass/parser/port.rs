use std::num::NonZeroU16;

use nom::{
    character::complete::digit1,
    error::{ErrorKind, ParseError},
    Err as NomErr, IResult, Parser,
};

use crate::pgpass::DELIMITER_CHAR;

use super::field::wildcard;

fn non_zero_u16(s: &str) -> IResult<&str, NonZeroU16, PortError> {
    let Ok((remaining, digits)) = digit1::<_, nom::error::Error<_>>.parse(s) else {
        return Err(NomErr::Error(PortError::InvalidPort));
    };
    let Ok(num_u32) = digits.parse::<u32>() else {
        return Err(NomErr::Error(PortError::InvalidPort));
    };
    let Ok(num_u16) = num_u32.try_into() else {
        return Err(NomErr::Error(PortError::InvalidPortNumber(num_u32)));
    };
    let Some(num) = NonZeroU16::new(num_u16) else {
        return Err(NomErr::Error(PortError::InvalidPortNumber(num_u32)));
    };
    Ok((remaining, num))
}

pub fn port_number(s: &str) -> IResult<&str, Option<NonZeroU16>, PortError> {
    if let Ok((remaining, _)) = wildcard.parse(s) {
        Ok((remaining, None))
    } else if s.is_empty() || s.starts_with(DELIMITER_CHAR) {
        Err(NomErr::Error(PortError::Empty))
    } else {
        let (remaining, num) = non_zero_u16.parse(s)?;
        Ok((remaining, Some(num)))
    }
}

/// An error encountered when parsing an invalid port field in a pgpass file.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum PortError {
    /// The supplied port was empty. This is invalid; use the wildcard character `*`.
    #[error("Fields must not be empty (use * for wildcards).")]
    Empty,
    /// The port number could not be parsed (eg it contained characters other than digits,
    /// or was > u32::MAX).
    #[error("Could not parse the port number.")]
    InvalidPort,
    /// The number supplied was not a valid port number. Valid port numbers are in
    /// the range `1..=65535`.
    #[error("{0} is not a valid port number.")]
    InvalidPortNumber(u32),
    /// An unanticipated error from `nom`. This should not happen. If you observe
    /// this error, it is a bug.
    /// The field was not followed by it's delimiter
    #[error("The delimiter character was not found")]
    Undelimited,
    #[error("An unknown error occurred during parsing (kind: {0:?}).")]
    Unknown(ErrorKind),
}
impl ParseError<&str> for PortError {
    fn from_error_kind(_input: &str, kind: ErrorKind) -> Self {
        // We do NOT store the input. Otherwise, we may accidentally expose
        // passwords in logs.
        if kind == ErrorKind::Tag {
            Self::Undelimited
        } else {
            Self::Unknown(kind)
        }
    }

    fn append(_input: &str, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn simple() {
        let s = "123:abc";
        let expected = (":abc", Some(NonZeroU16::new(123).unwrap()));
        assert_eq!(port_number.parse(s).unwrap(), expected);

        let s = "*:abc";
        let expected = (":abc", None);
        assert_eq!(port_number.parse(s).unwrap(), expected);
    }

    #[test]
    fn zero_is_invalid() {
        let s = "0";
        let expected = PortError::InvalidPortNumber(0);
        let NomErr::Error(actual) = port_number.parse(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn above_u16_max_is_invalid() {
        let s = "65536";
        let expected = PortError::InvalidPortNumber(65536);
        let NomErr::Error(actual) = port_number.parse(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn invalid_characters() {
        let s = "abc";
        let expected = PortError::InvalidPort;
        let NomErr::Error(actual) = port_number.parse(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn empty() {
        let s = "";
        let expected = PortError::Empty;
        let NomErr::Error(actual) = port_number.parse(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);

        let s = ":";
        let expected = PortError::Empty;
        let NomErr::Error(actual) = port_number.parse(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);
    }
}
