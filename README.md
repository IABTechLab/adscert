# ads.cert

![Build/Test](https://github.com/IABTechLab/adscert/actions/workflows/go.yml/badge.svg)

**This is a proof of concept and not meant for use in its current form.**

This open-source library implements the Authenticated Connections protocol, published by IAB Tech Lab let advertising industry participants secure programmatic ad buying and selling using industry-standard cryptographic security protocols.


## Authenticated Connections Protocol

Authenticated Connections uses a standardized HTTP request header containing a signature that secures:

- URL being invoked
- Body of POST requests
- Timestamp, origin, and destination values

The signature and these factors show that the request came from the originator as claimed and hasn't been tampered with. The request header looks like the following:

```
X-Ads-Cert-Auth:
from=ssai-serving.tk&from_key=w8f316&invoking=ad-exchange.tk&nonce=u_sDzKMIp0eD&status=0&timestamp=210519T174337&to=exchange-holding-company.ga&to_key=bBvfZU; sigb=t1TupK6wn8pn&sigu=FQ5OQ6TmF2xU
```

| Field | Description |
| --- | --- |
| from | The domain of the party sending the request |
| from_key | The first 6 characters of the sending party’s public key |
| invoking | The domain for the URL hostname being invoked |
| nonce | Randomly generated number from the sending party in base64 encoded. |
| timestamp | The time of generating signature in format: YYMMDDTHHMMSS.  This should be in UTC. |
| to | The domain of the party receiving the signature |
| to_key | The first 6 characters of the receiving party’s public key |
| sigb | The signature over the message and body of the request |
| sigu | The signature over the message, body, and URL of the request |

## Architecture

- **Signatory`**- Main library that handles signing and verification operations.
- **Dns Resolver** - Discovers TXT records for a domain name (with the appropriate subdomains for policy and key records)
- **Domain Store** - Stores domain information for invoking and identity domains and the associated keys
- **Domain Indexer** - Uses the above components to maintain a list of domains used in signing/verification operations, runs background crawls to update domain records, stores private keys, calculates shared secrets for use by the Signatory.

## API Usage

The `Signatory` is available as a [standalone GRPC server](cmd/server/main.go). See the [GRPC/Protobuf interface](api/adscert.proto) for the full API details. The main function defintions are below:

- `rpc SignAuthenticatedConnection(AuthenticatedConnectionSignatureRequest) returns (AuthenticatedConnectionSignatureResponse) {}`
- `rpc VerifyAuthenticatedConnection(AuthenticatedConnectionVerificationRequest) returns (AuthenticatedConnectionVerificationResponse) {}`

Clients are available for various langauges: 
- Golang - [GRPC client available here](api/golang) or the Signatory can be use as an [in-process Go library](pkg/adscert/signatory/signatory_local_impl.go) directly.
- Java - Coming soon...
- C++ - Coming soon...


## Examples

### Start the verifier

--host_callsign is the domain of the verifying server

In this example we use exchange-holding-company.ga which
is leveraged in this insecure example to generate a consistent
private key.

Note: The private key generated here should never be used in a production environment.  This is for demo purposes only.

Its corresponding public key can be found by looking it up
```
dig TXT _delivery._adscert.exchange-holding-company.ga
TXT "v=adcrtd k=x25519 h=sha256 p=bBvfZUTPDGIFiOq-WivBoOEYWM5mA1kaEfpDaoYtfHg"
```

Start the verifying server
```
go run examples/verifier/server/verifier-server.go --host_callsign=exchange-holding-company.ga --logtostderr
```

### Start the signer

The signer willl periodically send requests to the verifying server.

--origin-callsign is the domain of the signer.

Like above, we use the domain to generate an inconsistent consistent private key for ssai-serving.tk

--url is the full url that we wish to send a signed request too.
This gets signed along with the --body in the request.

In this example we use ads.ad-exchange.tk which is not exchange-holding-company.ga.  We can see the link between the two based on the TXT records.
```
dig TXT _adscert.ad-exchange.tk
TXT	"v=adpf a=exchange-holding-company.ga"
dig TXT _delivery._adscert.exchange-holding-company.ga
TXT "v=adcrtd k=x25519 h=sha256 p=bBvfZUTPDGIFiOq-WivBoOEYWM5mA1kaEfpDaoYtfHg"
```

Start the signing server in a second shell.
```
go run examples/signer/example-signer.go --frequency 5s --logtostderr --body '{"sample": "request"}' --origin_callsign=ssai-serving.tk --url='http://ads.ad-exchange.tk:8090/request?param1=example&param2=another' --send_requests
```

The two services will output log to stderr

### Sign requests and log to file
Alternatively, you can start the signing server to periodically log the invocating url, signature, hashed url, and hashed request to a log file that can be verified offline.

Start the signing server to log to signature_log_file path.
```
go run examples/signer/example-signer.go --frequency 1s --logtostderr --body '{"sample": "request"}' --origin_callsign=ssai-serving.tk --url='http://ads.ad-exchange.tk:8090/request?param1=example&param2=another' --signature_log_file=requests.log
```

### Verify log file
The log parser verifier will verify all entries in the log file and output a summary.
```
go run examples/verifier/log-parser/verifier-parser.go --origin_callsign=ssai-serving.tk --host_callsign=exchange-holding-company.ga --logtostderr --signature_log_file=requests.log
```

### Use logger interface
`./internal/logger` directory holds global logger interface along with a `standard_golang_logger` implementation which is being used as default logger. Default log level is INFO. Using the `SetLoggerImpl()` method in `./internal/logger/logger.go` interface you can implement any custom logger and set it as global logger in your application.

### Modify workflows
You can add custom workflows and github actions to `.github/workflows` folder. Currently `go.yml` includes the build and release steps including creating and pushing a new tag. A new release and tag only gets created only on main branch and push event.
[More info](https://docs.github.com/en/actions/reference/events-that-trigger-workflows).

## Contributing
Report bugs, request features and suggest improvements [on Github](https://github.com/InteractiveAdvertisingBureau/adscert_server/issues)


Or open up a [pull request](https://github.com/InteractiveAdvertisingBureau/adscert_server/compare)
