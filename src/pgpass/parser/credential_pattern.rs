use std::{marker::PhantomData, num::NonZeroU16};

use nom::{
    bytes::complete::tag, character::complete::line_ending, combinator::opt, sequence::Tuple,
    Err as NomErr, IResult, Parser,
};

use crate::pgpass::{pattern::HasPasswordTrue, CredentialPattern, DELIMITER};

use super::{
    field::{field, required_field, FieldError},
    port::port_number,
    ParsingError,
};

fn field_delimiter(s: &str) -> IResult<&str, (), FieldError> {
    if let Ok((remaining, _)) = tag::<_, _, nom::error::Error<_>>(DELIMITER).parse(s) {
        Ok((remaining, ()))
    } else {
        Err(NomErr::Error(FieldError::Undelimited))
    }
}

fn hostname_field(s: &str) -> IResult<&str, Option<String>, ParsingError> {
    let (remaining, (hostname, _)) = match (field, field_delimiter).parse(s) {
        Ok(x) => x,
        Err(NomErr::Error(e)) => return Err(NomErr::Error(ParsingError::InvalidHostname(e))),
        _ => unreachable!(),
    };

    Ok((remaining, hostname))
}

fn port_field(s: &str) -> IResult<&str, Option<NonZeroU16>, ParsingError> {
    match (port_number, tag(DELIMITER)).parse(s) {
        // The generics get messed up if we use field_delimiter
        Ok((remaining, (port, _))) => Ok((remaining, port)),
        Err(NomErr::Error(e)) => Err(NomErr::Error(ParsingError::InvalidPort(e))),
        _ => unreachable!(),
    }
}

fn database_field(s: &str) -> IResult<&str, Option<String>, ParsingError> {
    let (remaining, (database, _)) = match (field, field_delimiter).parse(s) {
        Ok(x) => x,
        Err(NomErr::Error(e)) => return Err(NomErr::Error(ParsingError::InvalidDatabase(e))),
        _ => unreachable!(),
    };

    Ok((remaining, database))
}

fn username_field(s: &str) -> IResult<&str, Option<String>, ParsingError> {
    let (remaining, (username, _)) = match (field, field_delimiter).parse(s) {
        Ok(x) => x,
        Err(NomErr::Error(e)) => return Err(NomErr::Error(ParsingError::InvalidUsername(e))),
        _ => unreachable!(),
    };

    Ok((remaining, username))
}

fn password_field(s: &str) -> IResult<&str, String, ParsingError> {
    let (remaining, (password, delim, _)) =
        match (required_field, opt(field_delimiter), opt(line_ending)).parse(s) {
            Ok(x) => x,
            Err(NomErr::Error(e)) => return Err(NomErr::Error(ParsingError::InvalidPassword(e))),
            _ => unreachable!(),
        };
    if delim.is_some() {
        Err(NomErr::Error(ParsingError::UnrecognizedColumn))
    } else {
        Ok((remaining, password))
    }
}

pub fn credential_pattern(
    s: &str,
) -> IResult<&str, CredentialPattern<HasPasswordTrue>, ParsingError> {
    let (remaining, (hostname, port, database, username, password)) = (
        hostname_field,
        port_field,
        database_field,
        username_field,
        password_field,
    )
        .parse(s)?;

    Ok((
        remaining,
        CredentialPattern {
            hostname,
            port,
            database,
            username,
            password,
            _tag: PhantomData,
        },
    ))
}

#[cfg(test)]
mod test {
    use nom::Finish;

    use crate::pgpass::parser::port::PortError;

    use super::*;

    #[test]
    fn simple() {
        let s = "one:2:three:four:five";
        let expected = CredentialPattern {
            hostname: Some("one".to_string()),
            port: Some(NonZeroU16::new(2).unwrap()),
            database: Some("three".to_string()),
            username: Some("four".to_string()),
            password: "five".to_string(),
            _tag: PhantomData,
        };
        assert_eq!(credential_pattern(s).unwrap(), ("", expected.clone()));
    }

    #[test]
    fn newlines_are_ignored() {
        let s = "one:2:three:four:five";
        let expected = CredentialPattern {
            hostname: Some("one".to_string()),
            port: Some(NonZeroU16::new(2).unwrap()),
            database: Some("three".to_string()),
            username: Some("four".to_string()),
            password: "five".to_string(),
            _tag: PhantomData,
        };
        assert_eq!(
            credential_pattern(format!("{}\nabc", s).as_str()).unwrap(),
            ("abc", expected.clone())
        );
        assert_eq!(
            credential_pattern(format!("{}\r\nabc", s).as_str()).unwrap(),
            ("abc", expected.clone())
        );
    }

    #[test]
    fn wildcard() {
        let s = "*:2:three:four:five";
        let expected = CredentialPattern {
            hostname: None,
            port: Some(NonZeroU16::new(2).unwrap()),
            database: Some("three".to_string()),
            username: Some("four".to_string()),
            password: "five".to_string(),
            _tag: PhantomData,
        };
        assert_eq!(credential_pattern(s).unwrap(), ("", expected.clone()));

        let s = "one:*:three:four:five";
        let expected = CredentialPattern {
            hostname: Some("one".to_string()),
            port: None,
            database: Some("three".to_string()),
            username: Some("four".to_string()),
            password: "five".to_string(),
            _tag: PhantomData,
        };
        assert_eq!(credential_pattern(s).unwrap(), ("", expected.clone()));

        let s = "one:2:*:four:five";
        let expected = CredentialPattern {
            hostname: Some("one".to_string()),
            port: Some(NonZeroU16::new(2).unwrap()),
            database: None,
            username: Some("four".to_string()),
            password: "five".to_string(),
            _tag: PhantomData,
        };
        assert_eq!(credential_pattern(s).unwrap(), ("", expected.clone()));

        let s = "one:2:three:*:five";
        let expected = CredentialPattern {
            hostname: Some("one".to_string()),
            port: Some(NonZeroU16::new(2).unwrap()),
            database: Some("three".to_string()),
            username: None,
            password: "five".to_string(),
            _tag: PhantomData,
        };
        assert_eq!(credential_pattern(s).unwrap(), ("", expected.clone()));

        // Password is required
    }

    #[test]
    fn invalid_hostname() {
        let s = "one\\x:2:three:four:five";
        let expected = ParsingError::InvalidHostname(FieldError::InvalidEscape('x'));
        let NomErr::Error(actual) = credential_pattern(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);

        let s = ":2:three:four:five";
        let expected = ParsingError::InvalidHostname(FieldError::Empty);
        let NomErr::Error(actual) = credential_pattern(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn invalid_port() {
        let s = "one:0:three:four:five";
        let expected = ParsingError::InvalidPort(PortError::InvalidPortNumber(0));
        let NomErr::Error(actual) = credential_pattern(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);

        let s = "one:65536:three:four:five";
        let expected = ParsingError::InvalidPort(PortError::InvalidPortNumber(65536));
        let NomErr::Error(actual) = credential_pattern(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);

        let s = "one:two:three:four:five";
        let expected = ParsingError::InvalidPort(PortError::InvalidPort);
        let NomErr::Error(actual) = credential_pattern(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);

        let s = "one::three:four:five";
        let expected = ParsingError::InvalidPort(PortError::Empty);
        let NomErr::Error(actual) = credential_pattern(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn invalid_database() {
        let s = "onex:2:thre\\xe:four:five";
        let expected = ParsingError::InvalidDatabase(FieldError::InvalidEscape('x'));
        let NomErr::Error(actual) = credential_pattern(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);

        let s = "onex:2::four:five";
        let expected = ParsingError::InvalidDatabase(FieldError::Empty);
        let NomErr::Error(actual) = credential_pattern(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn invalid_username() {
        let s = "one:2:three:fo\\xur:five";
        let expected = ParsingError::InvalidUsername(FieldError::InvalidEscape('x'));
        let NomErr::Error(actual) = credential_pattern(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);

        let s = "one:2:three::five";
        let expected = ParsingError::InvalidUsername(FieldError::Empty);
        let NomErr::Error(actual) = credential_pattern(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn password_is_required() {
        let s = "one:2:three:four:*";
        let expected = ParsingError::InvalidPassword(FieldError::Required);
        let NomErr::Error(actual) = credential_pattern(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn invalid_password() {
        let s = "one:2:three:four:fiv\\xe";
        let expected = ParsingError::InvalidPassword(FieldError::InvalidEscape('x'));
        let NomErr::Error(actual) = credential_pattern(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);

        let s = "one:2:three:four:";
        let expected = ParsingError::InvalidPassword(FieldError::Empty);
        let NomErr::Error(actual) = credential_pattern(s).err().unwrap() else {
            unreachable!()
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn unrecogize_column() {
        let s = "one:2:three:four:five:six";
        let actual = credential_pattern.parse(s).finish().err();
        assert_eq!(actual, Some(ParsingError::UnrecognizedColumn));
    }
}
