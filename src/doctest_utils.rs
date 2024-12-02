//! Utilities for improving the legibility of doc tests.

#![allow(unused)]

pub mod fake_postgres {
    use crate::Credentials;
    pub struct Config;
    impl Config {
        pub fn connect<T>(&self, _tls: T) -> Result<(), Error> {
            Ok(())
        }
    }
    impl From<Credentials> for Config {
        fn from(_: Credentials) -> Self {
            Self
        }
    }

    #[derive(thiserror::Error, Debug)]
    pub enum Error {}
}
