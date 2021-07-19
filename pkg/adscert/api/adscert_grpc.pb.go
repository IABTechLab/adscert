// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package api

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// AdsCertSignatoryClient is the client API for AdsCertSignatory service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AdsCertSignatoryClient interface {
	SignAuthenticatedConnection(ctx context.Context, in *AuthenticatedConnectionSignatureRequest, opts ...grpc.CallOption) (*AuthenticatedConnectionSignatureResponse, error)
	VerifyAuthenticatedConnection(ctx context.Context, in *AuthenticatedConnectionVerificationRequest, opts ...grpc.CallOption) (*AuthenticatedConnectionVerificationResponse, error)
	VerifyAuthenticatedConnectionBatch(ctx context.Context, in *AuthenticatedConnectionVerificationBatchRequest, opts ...grpc.CallOption) (*AuthenticatedConnectionVerificationBatchResponse, error)
}

type adsCertSignatoryClient struct {
	cc grpc.ClientConnInterface
}

func NewAdsCertSignatoryClient(cc grpc.ClientConnInterface) AdsCertSignatoryClient {
	return &adsCertSignatoryClient{cc}
}

func (c *adsCertSignatoryClient) SignAuthenticatedConnection(ctx context.Context, in *AuthenticatedConnectionSignatureRequest, opts ...grpc.CallOption) (*AuthenticatedConnectionSignatureResponse, error) {
	out := new(AuthenticatedConnectionSignatureResponse)
	err := c.cc.Invoke(ctx, "/api.AdsCertSignatory/SignAuthenticatedConnection", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *adsCertSignatoryClient) VerifyAuthenticatedConnection(ctx context.Context, in *AuthenticatedConnectionVerificationRequest, opts ...grpc.CallOption) (*AuthenticatedConnectionVerificationResponse, error) {
	out := new(AuthenticatedConnectionVerificationResponse)
	err := c.cc.Invoke(ctx, "/api.AdsCertSignatory/VerifyAuthenticatedConnection", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *adsCertSignatoryClient) VerifyAuthenticatedConnectionBatch(ctx context.Context, in *AuthenticatedConnectionVerificationBatchRequest, opts ...grpc.CallOption) (*AuthenticatedConnectionVerificationBatchResponse, error) {
	out := new(AuthenticatedConnectionVerificationBatchResponse)
	err := c.cc.Invoke(ctx, "/api.AdsCertSignatory/VerifyAuthenticatedConnectionBatch", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AdsCertSignatoryServer is the server API for AdsCertSignatory service.
// All implementations must embed UnimplementedAdsCertSignatoryServer
// for forward compatibility
type AdsCertSignatoryServer interface {
	SignAuthenticatedConnection(context.Context, *AuthenticatedConnectionSignatureRequest) (*AuthenticatedConnectionSignatureResponse, error)
	VerifyAuthenticatedConnection(context.Context, *AuthenticatedConnectionVerificationRequest) (*AuthenticatedConnectionVerificationResponse, error)
	VerifyAuthenticatedConnectionBatch(context.Context, *AuthenticatedConnectionVerificationBatchRequest) (*AuthenticatedConnectionVerificationBatchResponse, error)
	mustEmbedUnimplementedAdsCertSignatoryServer()
}

// UnimplementedAdsCertSignatoryServer must be embedded to have forward compatible implementations.
type UnimplementedAdsCertSignatoryServer struct {
}

func (UnimplementedAdsCertSignatoryServer) SignAuthenticatedConnection(context.Context, *AuthenticatedConnectionSignatureRequest) (*AuthenticatedConnectionSignatureResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SignAuthenticatedConnection not implemented")
}
func (UnimplementedAdsCertSignatoryServer) VerifyAuthenticatedConnection(context.Context, *AuthenticatedConnectionVerificationRequest) (*AuthenticatedConnectionVerificationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method VerifyAuthenticatedConnection not implemented")
}
func (UnimplementedAdsCertSignatoryServer) VerifyAuthenticatedConnectionBatch(context.Context, *AuthenticatedConnectionVerificationBatchRequest) (*AuthenticatedConnectionVerificationBatchResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method VerifyAuthenticatedConnectionBatch not implemented")
}
func (UnimplementedAdsCertSignatoryServer) mustEmbedUnimplementedAdsCertSignatoryServer() {}

// UnsafeAdsCertSignatoryServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AdsCertSignatoryServer will
// result in compilation errors.
type UnsafeAdsCertSignatoryServer interface {
	mustEmbedUnimplementedAdsCertSignatoryServer()
}

func RegisterAdsCertSignatoryServer(s grpc.ServiceRegistrar, srv AdsCertSignatoryServer) {
	s.RegisterService(&AdsCertSignatory_ServiceDesc, srv)
}

func _AdsCertSignatory_SignAuthenticatedConnection_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthenticatedConnectionSignatureRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AdsCertSignatoryServer).SignAuthenticatedConnection(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.AdsCertSignatory/SignAuthenticatedConnection",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AdsCertSignatoryServer).SignAuthenticatedConnection(ctx, req.(*AuthenticatedConnectionSignatureRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AdsCertSignatory_VerifyAuthenticatedConnection_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthenticatedConnectionVerificationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AdsCertSignatoryServer).VerifyAuthenticatedConnection(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.AdsCertSignatory/VerifyAuthenticatedConnection",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AdsCertSignatoryServer).VerifyAuthenticatedConnection(ctx, req.(*AuthenticatedConnectionVerificationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AdsCertSignatory_VerifyAuthenticatedConnectionBatch_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthenticatedConnectionVerificationBatchRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AdsCertSignatoryServer).VerifyAuthenticatedConnectionBatch(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.AdsCertSignatory/VerifyAuthenticatedConnectionBatch",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AdsCertSignatoryServer).VerifyAuthenticatedConnectionBatch(ctx, req.(*AuthenticatedConnectionVerificationBatchRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// AdsCertSignatory_ServiceDesc is the grpc.ServiceDesc for AdsCertSignatory service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AdsCertSignatory_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "api.AdsCertSignatory",
	HandlerType: (*AdsCertSignatoryServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SignAuthenticatedConnection",
			Handler:    _AdsCertSignatory_SignAuthenticatedConnection_Handler,
		},
		{
			MethodName: "VerifyAuthenticatedConnection",
			Handler:    _AdsCertSignatory_VerifyAuthenticatedConnection_Handler,
		},
		{
			MethodName: "VerifyAuthenticatedConnectionBatch",
			Handler:    _AdsCertSignatory_VerifyAuthenticatedConnectionBatch_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/adscert.proto",
}
