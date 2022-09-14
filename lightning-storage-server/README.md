# Try it

```sh
cargo run --bin lss-cli init

cargo run --bin lssd

cargo run --bin lss-cli put xx1 0 11
# will conflict
cargo run --bin lss-cli put xx1 0 11

cargo run --bin lss-cli put xy1 0 11
cargo run --bin lss-cli put xy2 0 22

cargo run --bin lss-cli get xx
cargo run --bin lss-cli get xy
cargo run --bin lss-cli get xy1
```
