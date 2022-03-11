#!/usr/bin/env bash

rm -rf ./target/doc
cargo doc --document-private-items --no-deps --release
rm -rf ./docs
# Change "ethsig-rs" to the name of the crate
echo "<meta http-equiv=\"refresh\" content=\"0; url=ethsig-rs\">" > target/doc/index.html
cp -r target/doc ./docs
