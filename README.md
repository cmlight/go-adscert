# go-adscert
A proof-of-concept Go language implementation.

This repository was created to inform design goals and get initial feedback regarding the integrator API.  It's not for production use.  The actual implementation will be hosted under a separate repository that's not yet available.

If you want to exercise this code for entertainment value:

```
git clone https://github.com/cmlight/go-adscert.git
cd go-adscert/
go run examples/demoserver/main.go --host_callsign=exchange-holding-company.ga --logtostderr
```

In a separate terminal, run the HTTP client:

```
go run examples/democlient/main.go --frequency 5s --logtostderr --body '{"sample": "request"}' --origin_callsign=ssai-serving.tk --url='http://ads.ad-exchange.tk:8090/request?param1=example&param2=another' --send_requests
```

This will perform real DNS lookups to resolve the keys published for these domains.  the "ads.ad-exchange.tk" hostname will resolve to 127.0.0.1 so that you can run this locally without needing any special configuration.

```
$ host ads.ad-exchange.tk
ads.ad-exchange.tk has address 127.0.0.1
```

The first request or two will not validate since both client and server need to discover each others' public keys.  After that, they should start validating.  You should see some DNS events also being logged by the client and server.

```
You invoked http://ads.ad-exchange.tk:8090/request?param1=example&param2=another with headers map[Accept-Encoding:[gzip] Content-Length:[21] User-Agent:[Go-http-client/1.1] X-Ads-Cert-Auth:[from=ssai-serving.tk&from_key=w8f316&invoking=ad-exchange.tk&nonce=ZwIwT47FUEs_&status=0&timestamp=210504T191544&to
=exchange-holding-company.ga&to_key=bBvfZU; sigb=ZFv69AKdCGKS&sigu=VGQWhpfXYQrj]] and verification true true
```
You can inspect the static DNS records for the simulated parties:

```
$ host -t TXT _adscert.ad-exchange.tk
_adscert.ad-exchange.tk descriptive text "v=adpf a=exchange-holding-company.ga"
$ host -t TXT _delivery._adscert.exchange-holding-company.ga
_delivery._adscert.exchange-holding-company.ga descriptive text "v=adcrtd k=x25519 h=sha256 p=bBvfZUTPDGIFiOq-WivBoOEYWM5mA1kaEfpDaoYtfHg"
$ host -t TXT _delivery._adscert.ssai-serving.tk
_delivery._adscert.ssai-serving.tk descriptive text "v=adcrtd k=x25519 h=sha256 p=w8f3160kEklY-nKuxogvn5PsZQLfkWWE0gUq_4JfFm8"
```
