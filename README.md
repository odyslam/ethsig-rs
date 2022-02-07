# Ethsig-rs

A Cloudflare worker that enables any backend service to use Sign In With Ethereum (SIWE) as an authetnication method.

The worker is an implementation of the SIWE standard to authorize users based on their Ethereum accounts.

The cloudflare worker supports an endpoint called `/authorize`, which is called for a user to sign-in or sign-up. The worker creates salts the authorization request and creates a token for the user to use when making authorized API calls. The token is also the key in a simple KV store that is used by a worker to retrieve authorization information about the user.

We leverage the worker's ability to auto-expire keys, which we set to last up to the point where the SIWE message expires. That way we can be certain that if a key exists in the KV Store, it must be valid still.Moreover, we don't have to deal with stale authorizations.

This worker is developped to power a new set of tools for compensating contributors in DAOs.

## Usage

With `wrangler`, you can build, test, and deploy your Worker with the following commands:

```bash
# compiles your project to WebAssembly and will warn of any issues
wrangler build

# run your Worker in an ideal development workflow (with a local server, file watcher & more)
wrangler dev

# deploy your Worker globally to the Cloudflare network (update your wrangler.toml file for configuration)
wrangler publish
```

Read the latest `worker` crate documentation here: https://docs.rs/worker

## WebAssembly

`workers-rs` (the Rust SDK for Cloudflare Workers used in this template) is meant to be executed as
compiled WebAssembly, and as such so **must** all the code you write and depend upon. All crates and
modules used in Rust-based Workers projects have to compile to the `wasm32-unknown-unknown` triple.

Read more about this on the [`workers-rs` project README](https://github.com/cloudflare/workers-rs).

