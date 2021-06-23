
## Signatory GRPC Client for Go

The adscert signatory can be run as a standalone GRPC server with Go clients generated from the `adscert.proto` file. A basic client that follows the `AuthenticatedConnectionsSignatory` interface is available in the [`signatory`](../../pkg/adscert/signatory) package to make RPC calls with timeouts and error handling.

See [`/examples/client/signer-client.go`](../../examples/client/signer-client.go) for example usage of the GRPC client connecting to the server.
