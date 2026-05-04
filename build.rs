// SPDX-License-Identifier: MIT
// NAPI-RS build glue. Runs at compile time to set up Node.js linkage and emit
// the platform-correct rustflags. Required by every NAPI-RS crate.
extern crate napi_build;

fn main() {
    napi_build::setup();
}
