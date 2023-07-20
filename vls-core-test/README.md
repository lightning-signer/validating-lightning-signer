# VLS Core Test

## Benchmarks

Currently available benches are:
- secp_bench
- commitment_bench

We can run the benchmarks using:

```
cargo bench --bench <name of bench>
```

Since we are using criterion we will get plots and reports generated for the bench run(s) in `target/criterion`.

To check them out, use the following python command to spin a server
```
python -m http.server 8080 --directory ./target/criterion/
```

Open the [report page](localhost:8080/report) in a browser.