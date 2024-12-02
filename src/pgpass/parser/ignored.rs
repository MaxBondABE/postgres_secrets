use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{line_ending, none_of},
    combinator::opt,
    multi::many0,
    sequence::{preceded, Tuple},
    IResult, Parser,
};

use crate::pgpass::COMMENT;

fn blank_line(s: &str) -> IResult<&str, ()> {
    let (remaining, _) = line_ending.parse(s)?;
    Ok((remaining, ()))
}

fn comment(s: &str) -> IResult<&str, ()> {
    let (remaining, _) = (
        preceded(tag(COMMENT), many0(none_of("\r\n"))),
        opt(line_ending),
    )
        .parse(s)?;
    Ok((remaining, ()))
}

pub fn ignored(s: &str) -> IResult<&str, ()> {
    alt((blank_line, comment)).parse(s)
}

#[cfg(test)]
pub mod test {
    use super::*;
    use nom::Parser;

    #[test]
    fn simple_comment() {
        let s = "# Foo";
        let expected = ("", ());
        assert_eq!(comment.parse(s), Ok(expected));
        assert_eq!(ignored.parse(s), Ok(expected));

        let s = "# Foo\nabc";
        let expected = ("abc", ());
        assert_eq!(comment.parse(s), Ok(expected));
        assert_eq!(ignored.parse(s), Ok(expected));

        let s = "# Foo\r\nabc";
        let expected = ("abc", ());
        assert_eq!(comment.parse(s), Ok(expected));
        assert_eq!(ignored.parse(s), Ok(expected));
    }

    #[test]
    fn simple_blank() {
        let s = "\nabc";
        let expected = ("abc", ());
        assert_eq!(blank_line.parse(s), Ok(expected));
        assert_eq!(ignored.parse(s), Ok(expected));

        let s = "\r\nabc";
        let expected = ("abc", ());
        assert_eq!(blank_line.parse(s), Ok(expected));
        assert_eq!(ignored.parse(s), Ok(expected));
    }
}
