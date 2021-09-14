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

You should see something like (with a different signature hex):

```text
This should succeed
Done
This should fail with a policy error
ERROR - FAILED PRECONDITION: policy failure: validate_delay: holder_selected_contest_delay too small
Caught expected exception policy failure: validate_delay: holder_selected_contest_delay too small
Signed initial commitment Signature(304402207159491d52f75dde969eb8849f1bfa9f5c085fd69d6d5f1a230bc949e896b87b0220491547350100472d686e3d825bc1b59a7c2860d738042a7f929acfe38c3b17fd01) localhost:8000:79:17
This should fail with a policy error
ERROR - FAILED PRECONDITION: policy failure: get_per_commitment_point: commitment_number 1 invalid when next_holder_commit_num is 0 bindgen_test.js:792:17
Caught expected exception policy failure: get_per_commitment_point: commitment_number 1 invalid when next_holder_commit_num is 0
Done
```
