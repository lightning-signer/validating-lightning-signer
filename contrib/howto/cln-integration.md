## Run CLN Integration Tests

Setup, configure, build and run the standard tests:

    make

Might need to increase open file limit if running all tests:

    ulimit -n 10000

Run tests:

    make -k test-all VLS_MODE=cln:socket

Using in-place VLS:

    make -k test-all VLS_MODE=cln:inplace

Run tests w/ VLS in permissive mode:

    make -k test-all VLS_MODE=cln:socket VLS_PERMISSIVE=1

Summarize results:

    scripts/summary all.log

Run a single test:

    make test-one TEST=tests/test_pay.py::test_pay
    make test-one TEST=tests/test_pay.py::test_pay VLS_MODE=cln:inplace
    make test-one TEST=tests/test_pay.py::test_pay VLS_MODE=cln:socket

Run a single test with native hsmd:

    make test-one TEST=tests/test_pay.py::test_pay VLS_MODE=cln:native

See [VLS Environment Variables](./env-vars.md) for additional settings.
