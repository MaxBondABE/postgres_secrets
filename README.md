`postgres_secrets` - Load Postgres credentials securely
-------------------------------------------------------

`postgres_secrets` allows you to load credentials from a file in standard ways that
are compatible with the Postgres tooling ecosystem.

Currently, only the [`pgpass`](https://www.postgresql.org/docs/current/libpq-pgpass.html)
format is supported. Support for [`connection service files`](https://www.postgresql.org/docs/current/libpq-pgservice.html)
may be implemented in the future.

# Use cases

- **Command line tools.** `postgres_secrets` uses the same [pgpass format](https://www.postgresql.org/docs/current/libpq-pgpass.html)
    as `psql`. This gives command-line users a seamless experience between `psql` and tools
    written with `postgres_secrets`.
- **In container environments.** `postgres_secrets` makes it easy to pass credentials
    to a container using tools like Docker secrets.

# Key features

## Simple, ergonomic API

- The API uses well-known Rust design patterns, and integrates with the `postgres` crate
- This is all it takes to connect to a database:

```rust
let pgpass = postgres_secrets::PgPass::load()?; // Looks for the pgpass file in it's default location
let creds = pgpass.query()
    .hostname("example.com")?
    .find()?
    .unwrap();
let config: postgres::Config = creds.into();
let db = config.connect(tls)?;
```

## Rock solid and well tested

- The test suite includes [property tests](https://www.postgresql.org/docs/current/libpq-pgpass.html),
    meaning the library has been tested against many randomly-generated pathological inputs.
- While it's possible the library has bugs, you are unlikely to encounter them in normal usage.

## Small, easily auditable codebase

- For those concerned about supply-chain attacks, `postgres_secrets` can be audited in an afternoon.
- All of it's dependencies are canonical, well-known crates.
- The license is public domain, making it easy to fork or vendor.

# Caveats

- This does not behave precisely the same as the parser in `libpq`.
    While unlikely, this could lead to bugs or confusing behavior
    in some circumstances.
- `libpq` is more permissive than this implementation. `libpq` will
    tolerate invalid escape sequences and extra columns. Because
    this behavior could cause bugs and confusing behavior, this
    implementation returns errors in these circumstances.
- `libpq` has special behavior when `localhost` is supplied as the
    hostname. This library does not support this.
- `libpq` performs a permissions check on the pgpass file, and will
    not open a file which is too permissive. This library does not
    perform this check.

# Documentation

[The documentation](https://docs.rs/postgres_secrets) is hosted on `docs.rs`.
