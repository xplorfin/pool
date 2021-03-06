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
	// 425 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x92, 0xcb, 0x6e, 0xd4, 0x30,
	0x14, 0x86, 0x95, 0x12, 0xd1, 0x19, 0xb7, 0x33, 0x6a, 0x2d, 0x10, 0x21, 0x05, 0x29, 0x8a, 0x54,
	0x18, 0xb1, 0x48, 0x44, 0xd9, 0xb1, 0x2b, 0xd0, 0x05, 0x12, 0x48, 0x28, 0xdd, 0xb1, 0x89, 0x3c,
	0xf1, 0x51, 0x62, 0xc9, 0x63, 0x07, 0xfb, 0xa4, 0x8b, 0x91, 0x58, 0xc0, 0x2b, 0xf0, 0x56, 0x6c,
	0x79, 0x05, 0x1e, 0x04, 0xd9, 0xb9, 0xcc, 0x0c, 0xb0, 0xb3, 0x3f, 0x1f, 0xff, 0xdf, 0xf1, 0x85,
	0x9c, 0x0b, 0x25, 0x50, 0x30, 0x29, 0xb6, 0x60, 0xb2, 0xd6, 0x68, 0xd4, 0xf4, 0xb8, 0xd5, 0x5a,
	0x9a, 0xb6, 0x8a, 0x9f, 0xd4, 0x5a, 0xd7, 0x12, 0x72, 0xd6, 0x8a, 0x9c, 0x29, 0xa5, 0x91, 0xa1,
	0xd0, 0xca, 0xf6, 0x65, 0xf1, 0x29, 0x1a, 0xc6, 0xc7, 0x4d, 0xe9, 0x57, 0x72, 0xfe, 0x7e, 0x4a,
	0x2a, 0xe0, 0x4b, 0x07, 0x16, 0xe9, 0x25, 0x59, 0x5a, 0x64, 0x08, 0x12, 0xac, 0x2d, 0x9d, 0x28,
	0x0a, 0x92, 0x60, 0x35, 0x2b, 0x16, 0x13, 0x75, 0x7b, 0xe8, 0x35, 0x39, 0x93, 0x8a, 0x97, 0xac,
	0xc3, 0xa6, 0xe4, 0x80, 0x4c, 0x48, 0x1b, 0x1d, 0x25, 0xc1, 0xea, 0xe4, 0xea, 0x51, 0x36, 0xf4,
	0x92, 0x7d, 0x50, 0xfc, 0xba, 0xc3, 0xe6, 0x5d, 0xbf, 0x5c, 0x2c, 0xe5, 0xc1, 0x3c, 0xfd, 0x16,
	0x10, 0xba, 0xef, 0xb7, 0xad, 0x56, 0x16, 0x5c, 0x03, 0x4e, 0x5b, 0xda, 0xae, 0xaa, 0x00, 0x38,
	0xf0, 0xb1, 0x01, 0x47, 0x6f, 0x47, 0xe8, 0xca, 0x9c, 0x87, 0x97, 0x1b, 0x56, 0x31, 0xa3, 0xb5,
	0xf2, 0xfa, 0xd3, 0x62, 0xe1, 0xe9, 0xc7, 0x01, 0xd2, 0xa7, 0x84, 0xf8, 0x34, 0x30, 0x46, 0x9b,
	0xe8, 0x5e, 0x12, 0xac, 0xe6, 0xc5, 0xdc, 0x91, 0x1b, 0x07, 0xd2, 0x2d, 0x59, 0x1e, 0x76, 0x49,
	0x29, 0x09, 0x1b, 0x6d, 0xfb, 0x53, 0xcf, 0x0b, 0x3f, 0x76, 0xac, 0xd5, 0x06, 0xbd, 0x21, 0x2c,
	0xfc, 0xd8, 0xf9, 0x19, 0xdf, 0x08, 0xb5, 0xf3, 0xf7, 0xe1, 0x0b, 0x4f, 0x27, 0xff, 0x63, 0x32,
	0x43, 0x69, 0xcb, 0x0a, 0x0c, 0x46, 0xa1, 0x2f, 0x38, 0x46, 0x69, 0xdf, 0x82, 0xc1, 0xab, 0x9f,
	0x01, 0x39, 0xd9, 0x9d, 0xdf, 0x50, 0xdc, 0x7f, 0x8e, 0x5b, 0x30, 0x77, 0xa2, 0x02, 0x1a, 0x4f,
	0xb7, 0xf9, 0xcf, 0x53, 0xc5, 0x17, 0xff, 0x5d, 0xeb, 0xaf, 0x31, 0x7d, 0xf6, 0xfd, 0xd7, 0xef,
	0x1f, 0x47, 0x49, 0x7a, 0x91, 0xdf, 0xbd, 0xcc, 0x5d, 0x5d, 0x6e, 0xfb, 0xc8, 0x7c, 0xf7, 0x7b,
	0x5e, 0x07, 0x2f, 0xe8, 0x0d, 0x09, 0x3f, 0x09, 0x55, 0xd3, 0x07, 0x53, 0x98, 0x9b, 0x8e, 0x8a,
	0x87, 0x7f, 0xd1, 0x21, 0xfc, 0xcc, 0x87, 0x13, 0x3a, 0xf3, 0xe1, 0x42, 0xd5, 0x6f, 0x9e, 0x7f,
	0xbe, 0xac, 0x05, 0x36, 0xdd, 0x3a, 0xab, 0xf4, 0x26, 0x97, 0xa2, 0x6e, 0x50, 0x09, 0x55, 0x4b,
	0xb6, 0xb6, 0xbd, 0x7d, 0xc8, 0x59, 0xdf, 0xf7, 0x7f, 0xef, 0xd5, 0x9f, 0x00, 0x00, 0x00, 0xff,
	0xff, 0x59, 0x23, 0xc3, 0x81, 0xc5, 0x02, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

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
	Ping(ctx context.Context, in *PingRequest, opts ...grpc.CallOption) (*PingResponse, error)
}

type initializerClient struct {
	cc grpc.ClientConnInterface
}

func NewInitializerClient(cc grpc.ClientConnInterface) InitializerClient {
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

func (c *initializerClient) Ping(ctx context.Context, in *PingRequest, opts ...grpc.CallOption) (*PingResponse, error) {
	out := new(PingResponse)
	err := c.cc.Invoke(ctx, "/poolrpc.Initializer/Ping", in, out, opts...)
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
	Ping(context.Context, *PingRequest) (*PingResponse, error)
}

// UnimplementedInitializerServer can be embedded to have forward compatible implementations.
type UnimplementedInitializerServer struct {
}

func (*UnimplementedInitializerServer) InitializeService(ctx context.Context, req *InitializeRequest) (*InitializeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method InitializeService not implemented")
}
func (*UnimplementedInitializerServer) Ping(ctx context.Context, req *PingRequest) (*PingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Ping not implemented")
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

func _Initializer_Ping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(InitializerServer).Ping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/poolrpc.Initializer/Ping",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(InitializerServer).Ping(ctx, req.(*PingRequest))
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
		{
			MethodName: "Ping",
			Handler:    _Initializer_Ping_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "initializer.proto",
}
