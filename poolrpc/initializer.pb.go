// Code generated by protoc-gen-go. DO NOT EDIT.
// source: initializer.proto

package poolrpc

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type InitializeRequest struct {
	//
	//Controls how poold initializes;
	//if stateless_init is true, then poold.macaroon won't be saved to disk,
	//and will instead be returned in InitResponse.
	//
	//Otherwise, poold.macaroon _will_ be saved to disk.
	StatelessInit        bool            `protobuf:"varint,1,opt,name=stateless_init,json=statelessInit,proto3" json:"stateless_init,omitempty"`
	LndAuthDetails       *LndAuthDetails `protobuf:"bytes,2,opt,name=lnd_auth_details,json=lndAuthDetails,proto3" json:"lnd_auth_details,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *InitializeRequest) Reset()         { *m = InitializeRequest{} }
func (m *InitializeRequest) String() string { return proto.CompactTextString(m) }
func (*InitializeRequest) ProtoMessage()    {}
func (*InitializeRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_fb6f168f5b28a3e9, []int{0}
}

func (m *InitializeRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_InitializeRequest.Unmarshal(m, b)
}
func (m *InitializeRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_InitializeRequest.Marshal(b, m, deterministic)
}
func (m *InitializeRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_InitializeRequest.Merge(m, src)
}
func (m *InitializeRequest) XXX_Size() int {
	return xxx_messageInfo_InitializeRequest.Size(m)
}
func (m *InitializeRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_InitializeRequest.DiscardUnknown(m)
}

var xxx_messageInfo_InitializeRequest proto.InternalMessageInfo

func (m *InitializeRequest) GetStatelessInit() bool {
	if m != nil {
		return m.StatelessInit
	}
	return false
}

func (m *InitializeRequest) GetLndAuthDetails() *LndAuthDetails {
	if m != nil {
		return m.LndAuthDetails
	}
	return nil
}

type InitializeResponse struct {
	//
	//Represents whether or not poold's initialization sequence succeeded.
	//If false, check the output of the `init_error` field.
	InitSucceeded bool `protobuf:"varint,1,opt,name=init_succeeded,json=initSucceeded,proto3" json:"init_succeeded,omitempty"`
	//
	//Raw byte data of the autogenerated poold.macaroon file.
	//
	//If initiated with stateless_init set to false, this field will be empty,
	//and poold.macaroon will instead be saved to
	//$POOLD_DIR/$NETWORK/poold.macaroon.
	PooldMacaroon []byte `protobuf:"bytes,2,opt,name=poold_macaroon,json=pooldMacaroon,proto3" json:"poold_macaroon,omitempty"`
	//
	//If poold initialization failed for some reason, contains the error string
	//of the initialization error.
	InitError            string   `protobuf:"bytes,3,opt,name=init_error,json=initError,proto3" json:"init_error,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *InitializeResponse) Reset()         { *m = InitializeResponse{} }
func (m *InitializeResponse) String() string { return proto.CompactTextString(m) }
func (*InitializeResponse) ProtoMessage()    {}
func (*InitializeResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_fb6f168f5b28a3e9, []int{1}
}

func (m *InitializeResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_InitializeResponse.Unmarshal(m, b)
}
func (m *InitializeResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_InitializeResponse.Marshal(b, m, deterministic)
}
func (m *InitializeResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_InitializeResponse.Merge(m, src)
}
func (m *InitializeResponse) XXX_Size() int {
	return xxx_messageInfo_InitializeResponse.Size(m)
}
func (m *InitializeResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_InitializeResponse.DiscardUnknown(m)
}

var xxx_messageInfo_InitializeResponse proto.InternalMessageInfo

func (m *InitializeResponse) GetInitSucceeded() bool {
	if m != nil {
		return m.InitSucceeded
	}
	return false
}

func (m *InitializeResponse) GetPooldMacaroon() []byte {
	if m != nil {
		return m.PooldMacaroon
	}
	return nil
}

func (m *InitializeResponse) GetInitError() string {
	if m != nil {
		return m.InitError
	}
	return ""
}

type LndAuthDetails struct {
	//
	//Host (whether a hostname or IP address) of the LND instance to connect to.
	//
	//Must not include the port number.
	Host string `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
	//
	//RPC port of the LND instance to connect to.
	//
	//Defaults to 10009 (LND's default RPC port).
	Port uint64 `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`
	//
	//Base64-encoded data of LND's admin macaroon to authenticate with.
	AdminMacaroon string `protobuf:"bytes,3,opt,name=admin_macaroon,json=adminMacaroon,proto3" json:"admin_macaroon,omitempty"`
	//
	//Base64-encoded data of LND's TLS certificate to authenticate with.
	TlsCert              string   `protobuf:"bytes,4,opt,name=tls_cert,json=tlsCert,proto3" json:"tls_cert,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LndAuthDetails) Reset()         { *m = LndAuthDetails{} }
func (m *LndAuthDetails) String() string { return proto.CompactTextString(m) }
func (*LndAuthDetails) ProtoMessage()    {}
func (*LndAuthDetails) Descriptor() ([]byte, []int) {
	return fileDescriptor_fb6f168f5b28a3e9, []int{2}
}

func (m *LndAuthDetails) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LndAuthDetails.Unmarshal(m, b)
}
func (m *LndAuthDetails) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LndAuthDetails.Marshal(b, m, deterministic)
}
func (m *LndAuthDetails) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LndAuthDetails.Merge(m, src)
}
func (m *LndAuthDetails) XXX_Size() int {
	return xxx_messageInfo_LndAuthDetails.Size(m)
}
func (m *LndAuthDetails) XXX_DiscardUnknown() {
	xxx_messageInfo_LndAuthDetails.DiscardUnknown(m)
}

var xxx_messageInfo_LndAuthDetails proto.InternalMessageInfo

func (m *LndAuthDetails) GetHost() string {
	if m != nil {
		return m.Host
	}
	return ""
}

func (m *LndAuthDetails) GetPort() uint64 {
	if m != nil {
		return m.Port
	}
	return 0
}

func (m *LndAuthDetails) GetAdminMacaroon() string {
	if m != nil {
		return m.AdminMacaroon
	}
	return ""
}

func (m *LndAuthDetails) GetTlsCert() string {
	if m != nil {
		return m.TlsCert
	}
	return ""
}

func init() {
	proto.RegisterType((*InitializeRequest)(nil), "poolrpc.InitializeRequest")
	proto.RegisterType((*InitializeResponse)(nil), "poolrpc.InitializeResponse")
	proto.RegisterType((*LndAuthDetails)(nil), "poolrpc.LndAuthDetails")
}

func init() { proto.RegisterFile("initializer.proto", fileDescriptor_fb6f168f5b28a3e9) }

var fileDescriptor_fb6f168f5b28a3e9 = []byte{
	// 390 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x92, 0xcd, 0x8e, 0xda, 0x30,
	0x10, 0x80, 0x15, 0x8a, 0x0a, 0x98, 0x82, 0x8a, 0x2f, 0x4d, 0xa1, 0x95, 0xa2, 0x48, 0xb4, 0xa8,
	0x87, 0x44, 0xa5, 0xb7, 0xde, 0xe8, 0xcf, 0xa1, 0x52, 0x7b, 0x09, 0xb7, 0x5e, 0x22, 0x93, 0x8c,
	0x12, 0x4b, 0xc6, 0xce, 0xda, 0x13, 0x0e, 0x48, 0x7b, 0xd8, 0xdd, 0x47, 0xd8, 0x47, 0xdb, 0x57,
	0xd8, 0x07, 0x59, 0xd9, 0x81, 0x00, 0xda, 0xbd, 0xd9, 0x9f, 0x67, 0xe6, 0x1b, 0xdb, 0x43, 0x26,
	0x5c, 0x72, 0xe4, 0x4c, 0xf0, 0x3d, 0xe8, 0xa8, 0xd2, 0x0a, 0x15, 0xed, 0x55, 0x4a, 0x09, 0x5d,
	0x65, 0xd3, 0x0f, 0x85, 0x52, 0x85, 0x80, 0x98, 0x55, 0x3c, 0x66, 0x52, 0x2a, 0x64, 0xc8, 0x95,
	0x34, 0x4d, 0x58, 0x78, 0x4d, 0x26, 0x7f, 0xda, 0xdc, 0x04, 0xae, 0x6a, 0x30, 0x48, 0xe7, 0x64,
	0x6c, 0x90, 0x21, 0x08, 0x30, 0x26, 0xb5, 0xa5, 0x7d, 0x2f, 0xf0, 0x16, 0xfd, 0x64, 0xd4, 0x52,
	0x9b, 0x43, 0x57, 0xe4, 0xad, 0x90, 0x79, 0xca, 0x6a, 0x2c, 0xd3, 0x1c, 0x90, 0x71, 0x61, 0xfc,
	0x4e, 0xe0, 0x2d, 0x86, 0xcb, 0x77, 0xd1, 0xc1, 0x1e, 0xfd, 0x95, 0xf9, 0xaa, 0xc6, 0xf2, 0x57,
	0x73, 0x9c, 0x8c, 0xc5, 0xc5, 0x3e, 0xbc, 0xf1, 0x08, 0x3d, 0xf7, 0x9b, 0x4a, 0x49, 0x03, 0xb6,
	0x01, 0xab, 0x4d, 0x4d, 0x9d, 0x65, 0x00, 0x39, 0xe4, 0xc7, 0x06, 0x2c, 0x5d, 0x1f, 0xa1, 0x0d,
	0xb3, 0x9e, 0x3c, 0xdd, 0xb2, 0x8c, 0x69, 0xa5, 0xa4, 0xd3, 0xbf, 0x49, 0x46, 0x8e, 0xfe, 0x3b,
	0x40, 0xfa, 0x91, 0x10, 0x57, 0x0d, 0xb4, 0x56, 0xda, 0x7f, 0x15, 0x78, 0x8b, 0x41, 0x32, 0xb0,
	0xe4, 0xb7, 0x05, 0xe1, 0x9e, 0x8c, 0x2f, 0xbb, 0xa4, 0x94, 0x74, 0x4b, 0x65, 0x9a, 0x5b, 0x0f,
	0x12, 0xb7, 0xb6, 0xac, 0x52, 0x1a, 0x9d, 0xa1, 0x9b, 0xb8, 0xb5, 0xf5, 0xb3, 0x7c, 0xcb, 0xe5,
	0xc9, 0xdf, 0x14, 0x1f, 0x39, 0xda, 0xfa, 0xdf, 0x93, 0x3e, 0x0a, 0x93, 0x66, 0xa0, 0xd1, 0xef,
	0xba, 0x80, 0x1e, 0x0a, 0xf3, 0x13, 0x34, 0x2e, 0xef, 0x3c, 0x32, 0x3c, 0xdd, 0x5f, 0x53, 0x3c,
	0xff, 0x8e, 0x35, 0xe8, 0x1d, 0xcf, 0x80, 0x4e, 0xdb, 0xd7, 0x7c, 0xf6, 0x55, 0xd3, 0xd9, 0x8b,
	0x67, 0xcd, 0x33, 0x86, 0x9f, 0x6e, 0x1f, 0x1e, 0xef, 0x3b, 0x41, 0x38, 0x8b, 0x77, 0x5f, 0x63,
	0x1b, 0x17, 0x9b, 0xa6, 0x64, 0x7c, 0x9a, 0x97, 0xef, 0xde, 0x97, 0x1f, 0x9f, 0xff, 0xcf, 0x0b,
	0x8e, 0x65, 0xbd, 0x89, 0x32, 0xb5, 0x8d, 0x05, 0x2f, 0x4a, 0x94, 0x5c, 0x16, 0x82, 0x6d, 0x4c,
	0x93, 0x76, 0x70, 0x6c, 0x5e, 0xbb, 0xa1, 0xf9, 0xf6, 0x14, 0x00, 0x00, 0xff, 0xff, 0x7b, 0xd8,
	0x20, 0xab, 0x70, 0x02, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// InitializerClient is the client API for Initializer service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type InitializerClient interface {
	//
	//Tells poold to initialize itself, create a macaroon,
	//and connect to LND.
	//
	//If InitRequest.stateless_init is true, InitResponse
	//will contain raw bytes of poold.macaroon (which won't be saved to disk).
	//Otherwise, InitResponse will simply return its success boolean.
	InitializeService(ctx context.Context, in *InitializeRequest, opts ...grpc.CallOption) (*InitializeResponse, error)
}

type initializerClient struct {
	cc *grpc.ClientConn
}

func NewInitializerClient(cc *grpc.ClientConn) InitializerClient {
	return &initializerClient{cc}
}

func (c *initializerClient) InitializeService(ctx context.Context, in *InitializeRequest, opts ...grpc.CallOption) (*InitializeResponse, error) {
	out := new(InitializeResponse)
	err := c.cc.Invoke(ctx, "/poolrpc.Initializer/InitializeService", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// InitializerServer is the server API for Initializer service.
type InitializerServer interface {
	//
	//Tells poold to initialize itself, create a macaroon,
	//and connect to LND.
	//
	//If InitRequest.stateless_init is true, InitResponse
	//will contain raw bytes of poold.macaroon (which won't be saved to disk).
	//Otherwise, InitResponse will simply return its success boolean.
	InitializeService(context.Context, *InitializeRequest) (*InitializeResponse, error)
}

// UnimplementedInitializerServer can be embedded to have forward compatible implementations.
type UnimplementedInitializerServer struct {
}

func (*UnimplementedInitializerServer) InitializeService(ctx context.Context, req *InitializeRequest) (*InitializeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method InitializeService not implemented")
}

func RegisterInitializerServer(s *grpc.Server, srv InitializerServer) {
	s.RegisterService(&_Initializer_serviceDesc, srv)
}

func _Initializer_InitializeService_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(InitializeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(InitializerServer).InitializeService(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/poolrpc.Initializer/InitializeService",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(InitializerServer).InitializeService(ctx, req.(*InitializeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Initializer_serviceDesc = grpc.ServiceDesc{
	ServiceName: "poolrpc.Initializer",
	HandlerType: (*InitializerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "InitializeService",
			Handler:    _Initializer_InitializeService_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "initializer.proto",
}