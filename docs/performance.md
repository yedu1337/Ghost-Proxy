# Performance profiling

The gateway has an opt-in pprof HTTP listener. It is disabled by default.
Set `pprof_address` in the server YAML to a loopback IP and port; non-loopback
addresses are rejected by configuration loading.

```yaml
pprof_address: "127.0.0.1:6060"
```

Restart the gateway, then collect a 30-second CPU profile and a heap profile:

```sh
go tool pprof http://127.0.0.1:6060/debug/pprof/profile?seconds=30
go tool pprof http://127.0.0.1:6060/debug/pprof/heap
```

For a repeatable microbenchmark of framed AEAD, padding, and payload handling:

```sh
go test ./pkg/transport -run '^$' -bench BenchmarkDataChannelRoundTrip -benchmem -count=5
```

This microbenchmark measures the frame codec in memory. It does not measure
TLS, sockets, end-to-end throughput, or latency. For those, run a controlled
destination through a configured client and gateway, keep the host/network,
Go version, padding and jitter settings fixed, and record the command and
results. Do not use an uncontrolled public destination for performance claims.

One preliminary run on Windows/amd64 with Go 1.27.0 and an AMD Ryzen 7 7435HS
reported 4.588 µs/op, 111.60 MB/s, 6,992 B/op, and 13 allocs/op. This was one
run with padding enabled and is included as a reproducible baseline, not as an
end-to-end performance claim. Repeat with `-count=5` on the target deployment
host before using the result in a thesis or release review.

| Date / environment | Workload | Padding / jitter | Throughput | p50 / p95 latency | Result artifact |
|---|---|---|---|---|---|
| Not run | Pending controlled end-to-end workload | Pending | Pending | Pending | Pending |
