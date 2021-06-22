// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.17.3
// source: api/adscert.proto

package api

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// RequestInfo conveys the basic parameters required for an authenticated
// connections signing or verify operation.
type RequestInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	InvocationHostname string `protobuf:"bytes,1,opt,name=invocation_hostname,json=invocationHostname,proto3" json:"invocation_hostname,omitempty"`
	UrlHash            []byte `protobuf:"bytes,2,opt,name=url_hash,json=urlHash,proto3" json:"url_hash,omitempty"`
	BodyHash           []byte `protobuf:"bytes,3,opt,name=body_hash,json=bodyHash,proto3" json:"body_hash,omitempty"`
}

func (x *RequestInfo) Reset() {
	*x = RequestInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_adscert_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RequestInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RequestInfo) ProtoMessage() {}

func (x *RequestInfo) ProtoReflect() protoreflect.Message {
	mi := &file_api_adscert_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RequestInfo.ProtoReflect.Descriptor instead.
func (*RequestInfo) Descriptor() ([]byte, []int) {
	return file_api_adscert_proto_rawDescGZIP(), []int{0}
}

func (x *RequestInfo) GetInvocationHostname() string {
	if x != nil {
		return x.InvocationHostname
	}
	return ""
}

func (x *RequestInfo) GetUrlHash() []byte {
	if x != nil {
		return x.UrlHash
	}
	return nil
}

func (x *RequestInfo) GetBodyHash() []byte {
	if x != nil {
		return x.BodyHash
	}
	return nil
}

// SignatureInfo captures the signature generated for the signing request.  It
// also provides structured metadata about the signature operation, useful in
// the integrating application for diagnostics.
type SignatureInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SignatureMessage string `protobuf:"bytes,1,opt,name=signature_message,json=signatureMessage,proto3" json:"signature_message,omitempty"`
	SigningStatus    string `protobuf:"bytes,2,opt,name=signing_status,json=signingStatus,proto3" json:"signing_status,omitempty"`
	FromDomain       string `protobuf:"bytes,3,opt,name=from_domain,json=fromDomain,proto3" json:"from_domain,omitempty"`
	FromKey          string `protobuf:"bytes,4,opt,name=from_key,json=fromKey,proto3" json:"from_key,omitempty"`
	InvokingDomain   string `protobuf:"bytes,5,opt,name=invoking_domain,json=invokingDomain,proto3" json:"invoking_domain,omitempty"`
	ToDomain         string `protobuf:"bytes,6,opt,name=to_domain,json=toDomain,proto3" json:"to_domain,omitempty"`
	ToKey            string `protobuf:"bytes,7,opt,name=to_key,json=toKey,proto3" json:"to_key,omitempty"`
}

func (x *SignatureInfo) Reset() {
	*x = SignatureInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_adscert_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignatureInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignatureInfo) ProtoMessage() {}

func (x *SignatureInfo) ProtoReflect() protoreflect.Message {
	mi := &file_api_adscert_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignatureInfo.ProtoReflect.Descriptor instead.
func (*SignatureInfo) Descriptor() ([]byte, []int) {
	return file_api_adscert_proto_rawDescGZIP(), []int{1}
}

func (x *SignatureInfo) GetSignatureMessage() string {
	if x != nil {
		return x.SignatureMessage
	}
	return ""
}

func (x *SignatureInfo) GetSigningStatus() string {
	if x != nil {
		return x.SigningStatus
	}
	return ""
}

func (x *SignatureInfo) GetFromDomain() string {
	if x != nil {
		return x.FromDomain
	}
	return ""
}

func (x *SignatureInfo) GetFromKey() string {
	if x != nil {
		return x.FromKey
	}
	return ""
}

func (x *SignatureInfo) GetInvokingDomain() string {
	if x != nil {
		return x.InvokingDomain
	}
	return ""
}

func (x *SignatureInfo) GetToDomain() string {
	if x != nil {
		return x.ToDomain
	}
	return ""
}

func (x *SignatureInfo) GetToKey() string {
	if x != nil {
		return x.ToKey
	}
	return ""
}

// AuthenticatedConnectionSignatureRequest contains the parameters for a signing
// request.
type AuthenticatedConnectionSignatureRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestInfo *RequestInfo `protobuf:"bytes,1,opt,name=request_info,json=requestInfo,proto3" json:"request_info,omitempty"`
	Timestamp   string       `protobuf:"bytes,2,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	Nonce       string       `protobuf:"bytes,3,opt,name=nonce,proto3" json:"nonce,omitempty"`
}

func (x *AuthenticatedConnectionSignatureRequest) Reset() {
	*x = AuthenticatedConnectionSignatureRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_adscert_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthenticatedConnectionSignatureRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthenticatedConnectionSignatureRequest) ProtoMessage() {}

func (x *AuthenticatedConnectionSignatureRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_adscert_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthenticatedConnectionSignatureRequest.ProtoReflect.Descriptor instead.
func (*AuthenticatedConnectionSignatureRequest) Descriptor() ([]byte, []int) {
	return file_api_adscert_proto_rawDescGZIP(), []int{2}
}

func (x *AuthenticatedConnectionSignatureRequest) GetRequestInfo() *RequestInfo {
	if x != nil {
		return x.RequestInfo
	}
	return nil
}

func (x *AuthenticatedConnectionSignatureRequest) GetTimestamp() string {
	if x != nil {
		return x.Timestamp
	}
	return ""
}

func (x *AuthenticatedConnectionSignatureRequest) GetNonce() string {
	if x != nil {
		return x.Nonce
	}
	return ""
}

// AuthenticatedConnectionSignatureResponse contains the results of a signing
// request, including any signature and relevant metadata. Multiple signatures
// can technically be present according to the specification.
type AuthenticatedConnectionSignatureResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SignatureInfo []*SignatureInfo `protobuf:"bytes,1,rep,name=signature_info,json=signatureInfo,proto3" json:"signature_info,omitempty"`
}

func (x *AuthenticatedConnectionSignatureResponse) Reset() {
	*x = AuthenticatedConnectionSignatureResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_adscert_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthenticatedConnectionSignatureResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthenticatedConnectionSignatureResponse) ProtoMessage() {}

func (x *AuthenticatedConnectionSignatureResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_adscert_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthenticatedConnectionSignatureResponse.ProtoReflect.Descriptor instead.
func (*AuthenticatedConnectionSignatureResponse) Descriptor() ([]byte, []int) {
	return file_api_adscert_proto_rawDescGZIP(), []int{3}
}

func (x *AuthenticatedConnectionSignatureResponse) GetSignatureInfo() []*SignatureInfo {
	if x != nil {
		return x.SignatureInfo
	}
	return nil
}

// AuthenticatedConnectionVerificationRequest contains a request for verifying
// signatures generated by another party.
type AuthenticatedConnectionVerificationRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestInfo      *RequestInfo `protobuf:"bytes,1,opt,name=request_info,json=requestInfo,proto3" json:"request_info,omitempty"`
	SignatureMessage []string     `protobuf:"bytes,2,rep,name=signature_message,json=signatureMessage,proto3" json:"signature_message,omitempty"`
}

func (x *AuthenticatedConnectionVerificationRequest) Reset() {
	*x = AuthenticatedConnectionVerificationRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_adscert_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthenticatedConnectionVerificationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthenticatedConnectionVerificationRequest) ProtoMessage() {}

func (x *AuthenticatedConnectionVerificationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_adscert_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthenticatedConnectionVerificationRequest.ProtoReflect.Descriptor instead.
func (*AuthenticatedConnectionVerificationRequest) Descriptor() ([]byte, []int) {
	return file_api_adscert_proto_rawDescGZIP(), []int{4}
}

func (x *AuthenticatedConnectionVerificationRequest) GetRequestInfo() *RequestInfo {
	if x != nil {
		return x.RequestInfo
	}
	return nil
}

func (x *AuthenticatedConnectionVerificationRequest) GetSignatureMessage() []string {
	if x != nil {
		return x.SignatureMessage
	}
	return nil
}

// AuthenticatedConnectionVerificationResponse contains the results of verifying
// signatures.
type AuthenticatedConnectionVerificationResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BodyValid bool `protobuf:"varint,1,opt,name=body_valid,json=bodyValid,proto3" json:"body_valid,omitempty"`
	UrlValid  bool `protobuf:"varint,2,opt,name=url_valid,json=urlValid,proto3" json:"url_valid,omitempty"`
}

func (x *AuthenticatedConnectionVerificationResponse) Reset() {
	*x = AuthenticatedConnectionVerificationResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_adscert_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthenticatedConnectionVerificationResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthenticatedConnectionVerificationResponse) ProtoMessage() {}

func (x *AuthenticatedConnectionVerificationResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_adscert_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthenticatedConnectionVerificationResponse.ProtoReflect.Descriptor instead.
func (*AuthenticatedConnectionVerificationResponse) Descriptor() ([]byte, []int) {
	return file_api_adscert_proto_rawDescGZIP(), []int{5}
}

func (x *AuthenticatedConnectionVerificationResponse) GetBodyValid() bool {
	if x != nil {
		return x.BodyValid
	}
	return false
}

func (x *AuthenticatedConnectionVerificationResponse) GetUrlValid() bool {
	if x != nil {
		return x.UrlValid
	}
	return false
}

var File_api_adscert_proto protoreflect.FileDescriptor

var file_api_adscert_proto_rawDesc = []byte{
	0x0a, 0x11, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x64, 0x73, 0x63, 0x65, 0x72, 0x74, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x03, 0x61, 0x70, 0x69, 0x22, 0x76, 0x0a, 0x0b, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x2f, 0x0a, 0x13, 0x69, 0x6e, 0x76, 0x6f, 0x63,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x12, 0x69, 0x6e, 0x76, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x19, 0x0a, 0x08, 0x75, 0x72, 0x6c, 0x5f,
	0x68, 0x61, 0x73, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x75, 0x72, 0x6c, 0x48,
	0x61, 0x73, 0x68, 0x12, 0x1b, 0x0a, 0x09, 0x62, 0x6f, 0x64, 0x79, 0x5f, 0x68, 0x61, 0x73, 0x68,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x62, 0x6f, 0x64, 0x79, 0x48, 0x61, 0x73, 0x68,
	0x22, 0xfc, 0x01, 0x0a, 0x0d, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x49, 0x6e,
	0x66, 0x6f, 0x12, 0x2b, 0x0a, 0x11, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x5f,
	0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x10, 0x73,
	0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12,
	0x25, 0x0a, 0x0e, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67,
	0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x1f, 0x0a, 0x0b, 0x66, 0x72, 0x6f, 0x6d, 0x5f, 0x64,
	0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x66, 0x72, 0x6f,
	0x6d, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x12, 0x19, 0x0a, 0x08, 0x66, 0x72, 0x6f, 0x6d, 0x5f,
	0x6b, 0x65, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x66, 0x72, 0x6f, 0x6d, 0x4b,
	0x65, 0x79, 0x12, 0x27, 0x0a, 0x0f, 0x69, 0x6e, 0x76, 0x6f, 0x6b, 0x69, 0x6e, 0x67, 0x5f, 0x64,
	0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x69, 0x6e, 0x76,
	0x6f, 0x6b, 0x69, 0x6e, 0x67, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x12, 0x1b, 0x0a, 0x09, 0x74,
	0x6f, 0x5f, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08,
	0x74, 0x6f, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x12, 0x15, 0x0a, 0x06, 0x74, 0x6f, 0x5f, 0x6b,
	0x65, 0x79, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x74, 0x6f, 0x4b, 0x65, 0x79, 0x22,
	0x92, 0x01, 0x0a, 0x27, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65,
	0x64, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x69, 0x67, 0x6e, 0x61,
	0x74, 0x75, 0x72, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x33, 0x0a, 0x0c, 0x72,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x10, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49,
	0x6e, 0x66, 0x6f, 0x52, 0x0b, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x6e, 0x66, 0x6f,
	0x12, 0x1c, 0x0a, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x12, 0x14,
	0x0a, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6e,
	0x6f, 0x6e, 0x63, 0x65, 0x22, 0x65, 0x0a, 0x28, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69,
	0x63, 0x61, 0x74, 0x65, 0x64, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x53,
	0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x39, 0x0a, 0x0e, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x5f, 0x69, 0x6e,
	0x66, 0x6f, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x53,
	0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0d, 0x73, 0x69,
	0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x22, 0x8e, 0x01, 0x0a, 0x2a,
	0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x64, 0x43, 0x6f, 0x6e,
	0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x56, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x33, 0x0a, 0x0c, 0x72, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x10, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x6e,
	0x66, 0x6f, 0x52, 0x0b, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x12,
	0x2b, 0x0a, 0x11, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x5f, 0x6d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x10, 0x73, 0x69, 0x67, 0x6e,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x22, 0x69, 0x0a, 0x2b,
	0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x64, 0x43, 0x6f, 0x6e,
	0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x56, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x62,
	0x6f, 0x64, 0x79, 0x5f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x09, 0x62, 0x6f, 0x64, 0x79, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x12, 0x1b, 0x0a, 0x09, 0x75, 0x72,
	0x6c, 0x5f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x75,
	0x72, 0x6c, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x32, 0x97, 0x02, 0x0a, 0x10, 0x41, 0x64, 0x73, 0x43,
	0x65, 0x72, 0x74, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x6f, 0x72, 0x79, 0x12, 0x7c, 0x0a, 0x1b,
	0x53, 0x69, 0x67, 0x6e, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65,
	0x64, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x2c, 0x2e, 0x61, 0x70,
	0x69, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x64, 0x43,
	0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2d, 0x2e, 0x61, 0x70, 0x69, 0x2e,
	0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x64, 0x43, 0x6f, 0x6e,
	0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x84, 0x01, 0x0a, 0x1d, 0x56,
	0x65, 0x72, 0x69, 0x66, 0x79, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74,
	0x65, 0x64, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x2f, 0x2e, 0x61,
	0x70, 0x69, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x64,
	0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x56, 0x65, 0x72, 0x69, 0x66, 0x69,
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x30, 0x2e,
	0x61, 0x70, 0x69, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65,
	0x64, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x56, 0x65, 0x72, 0x69, 0x66,
	0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22,
	0x00, 0x42, 0x2c, 0x5a, 0x2a, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x49, 0x41, 0x42, 0x54, 0x65, 0x63, 0x68, 0x4c, 0x61, 0x62, 0x2f, 0x61, 0x64, 0x73, 0x63, 0x65,
	0x72, 0x74, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x61, 0x70, 0x69, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_adscert_proto_rawDescOnce sync.Once
	file_api_adscert_proto_rawDescData = file_api_adscert_proto_rawDesc
)

func file_api_adscert_proto_rawDescGZIP() []byte {
	file_api_adscert_proto_rawDescOnce.Do(func() {
		file_api_adscert_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_adscert_proto_rawDescData)
	})
	return file_api_adscert_proto_rawDescData
}

var file_api_adscert_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_api_adscert_proto_goTypes = []interface{}{
	(*RequestInfo)(nil),                                 // 0: api.RequestInfo
	(*SignatureInfo)(nil),                               // 1: api.SignatureInfo
	(*AuthenticatedConnectionSignatureRequest)(nil),     // 2: api.AuthenticatedConnectionSignatureRequest
	(*AuthenticatedConnectionSignatureResponse)(nil),    // 3: api.AuthenticatedConnectionSignatureResponse
	(*AuthenticatedConnectionVerificationRequest)(nil),  // 4: api.AuthenticatedConnectionVerificationRequest
	(*AuthenticatedConnectionVerificationResponse)(nil), // 5: api.AuthenticatedConnectionVerificationResponse
}
var file_api_adscert_proto_depIdxs = []int32{
	0, // 0: api.AuthenticatedConnectionSignatureRequest.request_info:type_name -> api.RequestInfo
	1, // 1: api.AuthenticatedConnectionSignatureResponse.signature_info:type_name -> api.SignatureInfo
	0, // 2: api.AuthenticatedConnectionVerificationRequest.request_info:type_name -> api.RequestInfo
	2, // 3: api.AdsCertSignatory.SignAuthenticatedConnection:input_type -> api.AuthenticatedConnectionSignatureRequest
	4, // 4: api.AdsCertSignatory.VerifyAuthenticatedConnection:input_type -> api.AuthenticatedConnectionVerificationRequest
	3, // 5: api.AdsCertSignatory.SignAuthenticatedConnection:output_type -> api.AuthenticatedConnectionSignatureResponse
	5, // 6: api.AdsCertSignatory.VerifyAuthenticatedConnection:output_type -> api.AuthenticatedConnectionVerificationResponse
	5, // [5:7] is the sub-list for method output_type
	3, // [3:5] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_api_adscert_proto_init() }
func file_api_adscert_proto_init() {
	if File_api_adscert_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_adscert_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RequestInfo); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_adscert_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignatureInfo); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_adscert_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthenticatedConnectionSignatureRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_adscert_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthenticatedConnectionSignatureResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_adscert_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthenticatedConnectionVerificationRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_adscert_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthenticatedConnectionVerificationResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_api_adscert_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_adscert_proto_goTypes,
		DependencyIndexes: file_api_adscert_proto_depIdxs,
		MessageInfos:      file_api_adscert_proto_msgTypes,
	}.Build()
	File_api_adscert_proto = out.File
	file_api_adscert_proto_rawDesc = nil
	file_api_adscert_proto_goTypes = nil
	file_api_adscert_proto_depIdxs = nil
}
