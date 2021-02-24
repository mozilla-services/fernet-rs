fernet-rs
=========

[![dependency status](https://deps.rs/repo/github/mozilla-services/fernet-rs/status.svg)](https://deps.rs/repo/github/mozilla-services/fernet-rs)

An implementation of [fernet](https://github.com/fernet/spec) in Rust.

What is Fernet?
---------------

Fernet is a small library to help you encrypt parcels of data with optional expiry times. It's
great for tokens or exchanging small strings or blobs of data. Fernet is designed to be easy
to use, combining cryptographic primitives in a way that is hard to get wrong, prevents tampering
and gives you confidence that the token is legitimate. You should consider this if you need:

* Time limited authentication tokens in URLs or authorisation headers
* To send small blobs of encrypted data between two points with a static key
* Simple encryption of secrets to store to disk that can be read later
* Many more ...

Great! How do I start?
----------------------

Add fernet to your Cargo.toml:

    [dependencies]
    fernet = "0.1"

And then have a look at our [API documentation] online, or run "cargo doc --open" in your
project.

[API documentation online]: https://docs.rs/fernet

Testing Token Expiry
--------------------

By default fernet wraps operations in an attempt to be safe - you should never be able to
"hold it incorrectly". But we understand that sometimes you need to be able to do some
more complicated operations.

The major example of this is having your application test how it handles tokens that
have expired past their ttl.

To support this, we allow you to pass in timestamps to the `encrypt_at_time` and
`decrypt_at_time` functions, but these are behind a feature gate. To activate these
api's you need to add the following to Cargo.toml

    [dependencies]
    fernet = { version = "0.1", features = ["fernet_danger_timestamps"] }


