[Full Authenticated Connections Protocol Specification](https://iabtechlab.com/wp-content/uploads/2021/09/3-ads-cert-authenticated-connections-pc.pdf)

For more information about the ads.cert 2.0 suite of protocols, visit [https://iabtechlab.com/ads-cert](https://iabtechlab.com/ads-cert)

Contributing? Please review the IAB Tech Lab Open Source Initiative Governance guidelines [here](http://iabtechlab.com/opensource).

# ads.cert
## Authenticated Connections Protocol

**This is a proof of concept and not meant for use in its current form.**

This open-source library implements the **Authenticated Connections protocol**, published by the IAB Tech Lab, to enable advertising industry participants to secure programmatic ad buying and selling using industry-standard cryptographic security protocols.

Authenticated Connections uses a standardized **HTTP request header** containing a **signature** that secures the:

- URL being invoked
- Body of POST requests
- Timestamp, origin, and destination values

The signature over these elements authenticates that the request came from the claimed originator, and that its contents haven't been tampered with. 

Example request header:

```
X-Ads-Cert-Auth: 
from=adscerttestsigner.dev&from_key=LxqTmA&invoking=adscerttestverifier.dev&nonce=6Rpf4qD2LP_9&status=1&timestamp=220912T200513&to=adscerttestverifier.dev&to_key=uNzTFA; sigb=OcQzM62rkJk0&sigu=_44H63NN69Nb"
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

- **Signatory**- Main library that handles signing and verification operations.
- **Dns Resolver** - Discovers TXT records for a domain name (with the appropriate subdomains for policy and key records)
- **Domain Store** - Stores domain information for invoking and identity domains and the associated keys
- **Domain Indexer** - Uses the above components to maintain a list of domains used in signing/verification operations, runs background crawls to update domain records, stores private keys, calculates shared secrets for use by the Signatory.

## API Usage

The `Signatory` is available as a [gRPC server with ads.cert signing/verification capabilities](cmd/signatory.go). 
See the [GRPC/Protobuf interface](api/adscert.proto) for the full API details. The main function defintions are below:

- `rpc SignAuthenticatedConnection(AuthenticatedConnectionSignatureRequest) returns (AuthenticatedConnectionSignatureResponse) {}`
- `rpc VerifyAuthenticatedConnection(AuthenticatedConnectionVerificationRequest) returns (AuthenticatedConnectionVerificationResponse) {}`

Clients are available for various langauges: 
- Golang - [GRPC client available here](api/golang) or the Signatory can be use as an [in-process Go library](pkg/adscert/signatory/signatory_local_impl.go) directly.
- Java - Coming soon...
- C++ - Coming soon...


Commands are also provided to test the signing and verification functionality; details for running them is included below, see "Examples"

## Docker
-- deprecated --
The `Signatory` can be run from inside a Docker container:

```
$ make build-grpc-server-container
$ docker run -p 3000:3000 -p 3001:3001 adscert:latest --origin publica-ssai.com --private_key "${ADSCERT_SECRET}"
```

## Example Domains
Two domains, hosted by the tech lab, are availible for testing the signing and verification process:

- `aderttestsigner.dev`

- Public key:  LxqTmAIw8Beujvf42ni9V7r1wpVPPxtrD5nFRxlwy0U

- Private key: Ys83NKuuYxCVDUbmA671x3zAFsQ-EnNxmC2JLuBlGAU

- `aderttestverifier.dev`

- Public key:  uNzTFA2_QsCcxsVET8q-IDtEaDn_D3Q6xscev1TFsjc

- Private key: 6mkLbsTBKs0UwYLkBdw5ttJHzjpSZxof0A2rako-0qs

DNS records containing a public key have been published for each.

`_delivery._adscert.adscerttestsigner.dev. 3600 IN TXT "v=adcrtd k=x25519 h=sha256 p=LxqTmAIw8Beujvf42ni9V7r1wpVPPxtrD5nFRxlwy0U"`

`_delivery._adscert.adscerttestverifier.dev. 3600 IN TXT "v=adcrtd k=x25519 h=sha256 p=uNzTFA2_QsCcxsVET8q-IDtEaDn_D3Q6xscev1TFsjc"`

The DNS record consists of the following fields:

`v`
Set to the constant value “adcrtd” to indicate that this record provides an ads.cert delivery key. This token MUST appear at the start of the DNS record value.

`k`
Set to key algorithm identifier, designed for forward compatibility if we need to transition to another scheme in the future.  Currently this will always be set to “x25519” representing the X25519 Diffie-Hellman key exchange algorithm.

`h`
Set to the hash algorithm identifier, again designed for forward compatibility.  Currently this will always be set to “sha256” representing the SHA-256 secure hashing algorithm.

`p`
Values are 32 byte public keys represented as 43 byte base64 encoded strings, RFC 4648 “URL-safe” variant.

To retrieve the current, complete dns records for these test domains, run the following dig commands:

`dig _delivery._adscert.adscerttestsigner.dev TXT`

`dig _delivery._adscert.adscerttestverifier.dev TXT`


## Examples:
The following examples take advantage of the example domains above to test the signing and verification process against a signatory and web server. The signatory and web server can be run locally, or within a docker container.

To build and test the ads.cert authenticted connections binary **locally**, run the following command from within a local copy of this directory

### To generate an insecure private and public key pair, run:

`go run . basicinsecurekeygen`

**NOTE**

The private key generated in this fashion should never be used in a production environment, and are for demo purposes only.

The adscerttestsigner and adscerttestverifier used in these examples employ an insecure private and public key pair. 

The private keys of these domains are disclosed here, but any production implementation should **never** publicly disclose its private key 


### To sign and verify a message between adscerttestsigner.dev and adscerttestverifier.dev, follow these steps:


**Run the Test Signer Signatory:**

`go run . signatory --server_port 3000 --metrics_port 3001 --private_key "Ys83NKuuYxCVDUbmA671x3zAFsQ-EnNxmC2JLuBlGAU" --origin "adscerttestsigner.dev"`
- add an "&" to the end of the command to run in background, or run in a separate shell

**Sign a message to adscerttestverifier.dev (run against adscerttestsigner signatory):**

`go run . testsign --url "https://adscerttestver ifier.dev"`
- run twice
- will fail on first run because credentials for the invoked url do not yet exist in the signatory; credentials will be updated after the failure, and the signing attempt will succeed on the second run
receiving party must have a published public key for signing to succeed

**(Optional) kill the Test Signer Signatory:**

`ps`
- to find the psid the signatory is running under

`sudo kill -9 <psid>`

**Run the Test Verifier signatory:**

`go run . signatory --server_port 4000 --metrics_port 4001 --private_key "6mkLbsTBKs0UwYLkBdw5ttJHzjpSZxof0A2rako-0qs" --origin "adscerttestverifier.dev"`
- add an "&" to the end of the command to run in background, or run in a separate shell

**Verify the message (run against adscerttestverifier signatory):**

`go run . testverify --url "https://adscerttestverifier.dev" --signatureMessage "from=adscerttestsigner.dev&from_key=LxqTmA&invoking=adscerttestverifier.dev&nonce=mBJo7EYj9XF9&status=1&timestamp=220810T142237&to=adscerttestverifier.dev&to_key=uNzTFA; sigb=ugN9tqMd6h0p&sigu=pxQd8BV20lHg"`
- run twice
- will fail on first run because credentials for the signer do not yet exist in the verifier signatory; credentials will be updated after the failure, and the verification attempt will succeed on the second run
the signing and receiving/verifying parties must have published public keys for verification to succeed

### To Sign a Request, invoke it against a local web server, and verify the signature, do the following:

**Run the Test Signer Signatory:**

`go run . signatory --server_port 3000 --metrics_port 3001 --private_key "Ys83NKuuYxCVDUbmA671x3zAFsQ-EnNxmC2JLuBlGAU" --origin "adscerttestsigner.dev"`
- add an "&" to the end of the command to run in background, or run in a separate shell

**Sign a message to adscerttestverifier.dev (run against adscerttestsigner signatory):**

`go run . testsign --url "https://adscerttestverifier.dev"`
- run twice
- will fail on first run because credentials for the invoked url do not yet exist in the signatory; credentials will be updated after the failure, and the signing attempt will succeed on the second run
receiving party must have a published public key for signing to succeed

**(Optional) kill the Test Signer Signatory:**

`ps`
- to find the psid the signatory is running under

`sudo kill -9 <psid>`

**Run the Test Verifier signatory:**

`go run . signatory --server_port 4000 --metrics_port 4001 --private_key "6mkLbsTBKs0UwYLkBdw5ttJHzjpSZxof0A2rako-0qs" --origin "adscerttestverifier.dev"`
- add an "&" to the end of the command to run in background, or run in a separate shell

**Run the testreceiver web server:**

`go run . testreceiver --server_port 5000 --verifier_address localhost:4000`
- add an "&" to the end of the command to run in background, or run in a separate shell

**Send a signed request to the web server:**

`curl http://adscerttestverifier.dev:5000 -H "X-Ads-Cert-Auth: from=adscerttestsigner.dev&from_key=LxqTmA&invoking=adscerttestverifier.dev&nonce=6Rpf4qD2LP_9&status=1&timestamp=220912T200513&to=adscerttestverifier.dev&to_key=uNzTFA; sigb=OcQzM62rkJk0&sigu=_44H63NN69Nb"`


### Sign requests and log to file
logging for cmd based verification to be added

### Modify workflows
You can add custom workflows and github actions to `.github/workflows` folder. Currently `go.yml` includes the build and release steps including creating and pushing a new tag. A new release and tag only gets created only on main branch and push event.
[More info](https://docs.github.com/en/actions/reference/events-that-trigger-workflows).

## Contributing
Report bugs, request features and suggest improvements [on Github](https://github.com/InteractiveAdvertisingBureau/adscert_server/issues)

Or open up a [pull request](https://github.com/InteractiveAdvertisingBureau/adscert_server/compare)
