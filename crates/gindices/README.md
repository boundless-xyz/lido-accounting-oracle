# gindices

## Codegen

If you need to regenerate the gindices for any reason (e.g. the change in a network upgrade) you can modify the `gen_gindices.rs` file and then regenrate with

```sh
cargo run --features codegen > guest_gindices.rs
```
