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