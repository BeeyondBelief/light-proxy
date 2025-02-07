# light-proxy

`Light-proxy` is a simple and probably fast tcp server that can be used as a proxy one.

Currently supported proxy protocols are:

1. SOCKS5
2. SOCKS4

## Run

Run `light-proxy` as a socks5 proxy server:

```shell
light-proxy socks5 -l 0.0.0.0 -p 8000
```

See the help for more information about acceptable options:

```shell
light-proxy -h
```