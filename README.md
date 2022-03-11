# Ethsig-rs

A Cloudflare worker that enables any backend service to use Sign In With Ethereum (SIWE) as an authetnication method.

The worker is an implementation of the SIWE standard to authorize users based on their Ethereum accounts.

The Cloudflare worker supports an endpoint called `/authorize`, which is called for a user to sign-in or sign-up. The worker creates salts the authorization request and creates a token for the user to use when making authorized API calls. The token is also the key in a simple KV store that is used by a worker to retrieve authorization information about the user.

After that, the authentication can either be handled by the Cloudflare worker or by the API itself. If it's handled by the worker, we could direct all requests to the worker and then configure the worker to redirect authenticated requests to our API. If the authentication is handled directly by our API, it can plug into the KV store using Cloudflare's API and simply use the token to retrieve authorization information and verify that the requested API call is authorized.

The example assumes that it's used by some front-end as the authentication logic. For that reason

We leverage the worker's ability to auto-expire keys, which we set to last up to the point where the SIWE message expires. That way we can be certain that if a key exists in the KV Store, it must be valid still.Moreover, we don't have to deal with stale authorizations.

Ethsig was developed to be used in a product of the [Radicle](https://radicle.xyz) stack.

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


## Linting

```bash
cargo check --all
cargo +nightly fmt -- --check
cargo +nightly clippy --all --all-features -- -D warnings
```

## CI

The repository will automatically Lint and build the `rustdoc` for this worker on every new PR. The `rustdocs` are placed in `/docs`, so they can be automatically hosted in GitHub pages.

Make sure you change the link inside `gen-docs.sh` to the name of the crate. This redirection is required because GitHub pages will only serve `/docs/index.html` as the entrypoint. With the redirection, we point the user to the correct subpath where the `rustdoc` `index.html` exists.

The repository will auto-publish the worker on every new commit to `master`. Make sure you add `CF_API_TOKEN` to the secrets of the repo.

## WebAssembly

`workers-rs` (the Rust SDK for Cloudflare Workers used in this template) is meant to be executed as
compiled WebAssembly, and as such so **must** all the code you write and depend upon. All crates and
modules used in Rust-based Workers projects have to compile to the `wasm32-unknown-unknown` triple.

Read more about this on the [`workers-rs` project README](https://github.com/cloudflare/workers-rs).

