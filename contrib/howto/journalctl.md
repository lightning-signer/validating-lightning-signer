## Configuring journalctl

It is useful to use journalctl because it normalizes log timestamps
and can show multiple different server's entries in a time sorted log.

### Increasing retention

Edit `/etc/systemd/journald.conf`:
```
# 10x more overall storage
SystemMaxUse=40G

# 10x more burst capacity
RateLimitBurst=100000

# 10x more journal files
SystemMaxFiles=1000
```

Restart
```
sudo systemctl restart systemd-journald
```

### Useful commands

```
# limit to one service
journalctl -u vls-testnet.service

# select time range
journalctl --since "YYYY-MM-DD HH:MM:SS" --until "YYYY-MM-DD HH:MM:SS"

# how much disk is used?
journalctl --disk-usage

# what is the earliest entry?
journalctl | head
```

### Log filter script

The log filter script can be used to filter logs for information about specific
channels.

Using journalctl:
```
journalctl \
  --since 12:00 \
  --output=short-full | \
logfilter \
  --all \
  --funding=1f7a9acb92aa7b35f9758412b9bbd019f2d427e18e5911801ef289675e8caee1:0 \
  --dbid=47 \
  --channelid=02146e28a3d43205b99d93c758b18d302be0086655d5a23e9bea9a6509da907dbd2a00000000000000 \
  --watches
```

Using historical rolled (and compressed) logfiles:
```
logcat remote_hsmd_socket.log | \
logfilter \
  --proxy \
  --dbid=47
```
