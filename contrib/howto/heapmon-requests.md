## Using the `heapmon_requests` Feature

The heapmon feature can be used in development to track heap usage when handling requests.

To use the feature, when building VLS add a `VLS_BUILDARGS` value:
```
cd ~/lightning-signer/vls-hsmd && make VLS_BUILDARGS='--features heapmon_requests' build
```

You can control the threshold for "large" requests with the `VLS_HEAPMON_PEAK_THRESH`
env variable.  You can add the following line to the `~vls/.lightning-signer/testnet-setenv`
config file:
```
export VLS_HEAPMON_PEAK_THRESH=40000
```

With `heapmon_requests` enabled additional information about large
requests is logged at info level.

A good way to summarize the results is by grepping the logs:
```
grep 'Filtered' vlsd.log
[2023-08-16 14:18:28.580 vlsd/heapmon INFO] Filtered peak size for SignRemoteCommitmentTx is 33_764
[2023-08-16 14:18:30.375 vlsd/heapmon INFO] Filtered peak size for ValidateCommitmentTx is 32_776
[2023-08-16 14:18:31.511 vlsd/heapmon INFO] Filtered peak size for SignRemoteCommitmentTx is 32_000
[2023-08-16 14:25:42.817 vlsd/heapmon INFO] Filtered peak size for SignRemoteCommitmentTx is 30_832
```

Allocation backtraces can be found in the log.
