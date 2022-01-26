# Ethsig-rs

Example worker that uses ethers-rs and cloudflare workers to create an endpoint that verifies signed messages with an Ethereum address.

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

