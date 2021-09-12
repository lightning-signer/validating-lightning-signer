# Try this out

## Install pre-requisites

Ensure Firefox is installed.  Then:

```shell
# you may need:
# sudo apt install clang gcc-multilib build-essential

rustup target add wasm32-unknown-unknown
cargo install wasm-pack https
```

## Test on headless Firefox

```shell
wasm-pack test --firefox --headless 
```

## Run manually

```shell
wasm-pack build --target web --dev
http
```

In a browser load `http://localhost:8000/`, and look at the console log.

You should see something like:

```text
This should succeed
Done
This should fail with a policy error
ERROR - FAILED PRECONDITION: policy failure: validate_delay: holder_selected_contest_delay too small
Caught expected exception policy failure: validate_delay: holder_selected_contest_delay too small
Done
```
