// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: vstore/v1/types.proto

package v1

import (
	fmt "fmt"
	v1 "github.com/cometbft/cometbft/api/cometbft/crypto/v1"
	_ "github.com/cosmos/gogoproto/gogoproto"
	proto "github.com/cosmos/gogoproto/proto"
	_ "github.com/cosmos/gogoproto/types"
	github_com_cosmos_gogoproto_types "github.com/cosmos/gogoproto/types"
	io "io"
	math "math"
	math_bits "math/bits"
	time "time"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf
var _ = time.Kitchen

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// Transaction represents a transportable data payload.
// Transactions always contain a signer and a signature.
type Transaction struct {
	// Contains the signer public key and its type (32+1 bytes)
	Signer v1.PublicKey `protobuf:"bytes,1,opt,name=signer,proto3" json:"signer"`
	// Contains the signature of body (64 bytes)
	Signature []byte `protobuf:"bytes,2,opt,name=signature,proto3" json:"signature,omitempty"`
	// Contains the transaction hash (32 bytes)
	Hash []byte `protobuf:"bytes,3,opt,name=hash,proto3" json:"hash,omitempty"`
	// Contains the transaction timestamp
	Time time.Time `protobuf:"bytes,4,opt,name=time,proto3,stdtime" json:"time"`
	Len  uint32    `protobuf:"varint,5,opt,name=len,proto3" json:"len,omitempty"`
	// Contains the transaction body (arbitrary length)
	Body []byte `protobuf:"bytes,6,opt,name=body,proto3" json:"body,omitempty"`
}

func (m *Transaction) Reset()         { *m = Transaction{} }
func (m *Transaction) String() string { return proto.CompactTextString(m) }
func (*Transaction) ProtoMessage()    {}
func (*Transaction) Descriptor() ([]byte, []int) {
	return fileDescriptor_be4df92a94422b46, []int{0}
}
func (m *Transaction) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Transaction) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Transaction.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Transaction) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Transaction.Merge(m, src)
}
func (m *Transaction) XXX_Size() int {
	return m.Size()
}
func (m *Transaction) XXX_DiscardUnknown() {
	xxx_messageInfo_Transaction.DiscardUnknown(m)
}

var xxx_messageInfo_Transaction proto.InternalMessageInfo

func (m *Transaction) GetSigner() v1.PublicKey {
	if m != nil {
		return m.Signer
	}
	return v1.PublicKey{}
}

func (m *Transaction) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

func (m *Transaction) GetHash() []byte {
	if m != nil {
		return m.Hash
	}
	return nil
}

func (m *Transaction) GetTime() time.Time {
	if m != nil {
		return m.Time
	}
	return time.Time{}
}

func (m *Transaction) GetLen() uint32 {
	if m != nil {
		return m.Len
	}
	return 0
}

func (m *Transaction) GetBody() []byte {
	if m != nil {
		return m.Body
	}
	return nil
}

func init() {
	proto.RegisterType((*Transaction)(nil), "vstore.v1.Transaction")
}

func init() { proto.RegisterFile("vstore/v1/types.proto", fileDescriptor_be4df92a94422b46) }

var fileDescriptor_be4df92a94422b46 = []byte{
	// 301 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x44, 0x90, 0x41, 0x4b, 0xc3, 0x30,
	0x1c, 0xc5, 0x1b, 0x57, 0x87, 0xcb, 0x14, 0x24, 0x28, 0x84, 0xe1, 0xb2, 0xa1, 0x97, 0x9d, 0x12,
	0xa6, 0x17, 0xc1, 0x5b, 0xaf, 0x5e, 0xa4, 0xec, 0xe4, 0xad, 0xad, 0x59, 0x57, 0x6c, 0x9b, 0x92,
	0xa4, 0x85, 0x7e, 0x8b, 0x7d, 0xac, 0x1d, 0x77, 0xf4, 0x20, 0x2a, 0xed, 0x17, 0x91, 0xa4, 0xad,
	0xde, 0x5e, 0x5e, 0xfe, 0xef, 0xff, 0xcb, 0x0b, 0xbc, 0xae, 0x94, 0x16, 0x92, 0xb3, 0x6a, 0xcd,
	0x74, 0x5d, 0x70, 0x45, 0x0b, 0x29, 0xb4, 0x40, 0x93, 0xce, 0xa6, 0xd5, 0x7a, 0x76, 0x15, 0x8b,
	0x58, 0x58, 0x97, 0x19, 0xd5, 0x0d, 0xcc, 0x16, 0xb1, 0x10, 0x71, 0xca, 0x99, 0x3d, 0x85, 0xe5,
	0x96, 0xe9, 0x24, 0xe3, 0x4a, 0x07, 0x59, 0xd1, 0x0f, 0xcc, 0x23, 0x91, 0x71, 0x1d, 0x6e, 0x35,
	0x8b, 0x64, 0x5d, 0x68, 0x61, 0x08, 0xef, 0xbc, 0xee, 0x01, 0xb7, 0x9f, 0x00, 0x4e, 0x37, 0x32,
	0xc8, 0x55, 0x10, 0xe9, 0x44, 0xe4, 0xe8, 0x09, 0x8e, 0x55, 0x12, 0xe7, 0x5c, 0x62, 0xb0, 0x04,
	0xab, 0xe9, 0xfd, 0x9c, 0x0e, 0x79, 0xda, 0xe5, 0x69, 0xb5, 0xa6, 0x2f, 0x65, 0x98, 0x26, 0xd1,
	0x33, 0xaf, 0x3d, 0xf7, 0xf0, 0xb5, 0x70, 0xfc, 0x3e, 0x82, 0x6e, 0xe0, 0xc4, 0xa8, 0x40, 0x97,
	0x92, 0xe3, 0x93, 0x25, 0x58, 0x9d, 0xfb, 0xff, 0x06, 0x42, 0xd0, 0xdd, 0x05, 0x6a, 0x87, 0x47,
	0xf6, 0xc2, 0x6a, 0xf4, 0x08, 0x5d, 0xf3, 0x60, 0xec, 0x5a, 0xd8, 0x8c, 0x76, 0x6d, 0xe8, 0xd0,
	0x86, 0x6e, 0x86, 0x36, 0xde, 0x99, 0x21, 0xed, 0xbf, 0x17, 0xc0, 0xb7, 0x09, 0x74, 0x09, 0x47,
	0x29, 0xcf, 0xf1, 0xe9, 0x12, 0xac, 0x2e, 0x7c, 0x23, 0xcd, 0xfe, 0x50, 0xbc, 0xd5, 0x78, 0xdc,
	0xed, 0x37, 0xda, 0xbb, 0x3b, 0x34, 0x04, 0x1c, 0x1b, 0x02, 0x7e, 0x1a, 0x02, 0xf6, 0x2d, 0x71,
	0x8e, 0x2d, 0x71, 0x3e, 0x5a, 0xe2, 0xbc, 0x4e, 0xfe, 0x3e, 0x3c, 0x1c, 0x5b, 0xdc, 0xc3, 0x6f,
	0x00, 0x00, 0x00, 0xff, 0xff, 0x08, 0xe2, 0x89, 0x4a, 0x84, 0x01, 0x00, 0x00,
}

func (m *Transaction) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Transaction) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Transaction) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Body) > 0 {
		i -= len(m.Body)
		copy(dAtA[i:], m.Body)
		i = encodeVarintTypes(dAtA, i, uint64(len(m.Body)))
		i--
		dAtA[i] = 0x32
	}
	if m.Len != 0 {
		i = encodeVarintTypes(dAtA, i, uint64(m.Len))
		i--
		dAtA[i] = 0x28
	}
	n1, err1 := github_com_cosmos_gogoproto_types.StdTimeMarshalTo(m.Time, dAtA[i-github_com_cosmos_gogoproto_types.SizeOfStdTime(m.Time):])
	if err1 != nil {
		return 0, err1
	}
	i -= n1
	i = encodeVarintTypes(dAtA, i, uint64(n1))
	i--
	dAtA[i] = 0x22
	if len(m.Hash) > 0 {
		i -= len(m.Hash)
		copy(dAtA[i:], m.Hash)
		i = encodeVarintTypes(dAtA, i, uint64(len(m.Hash)))
		i--
		dAtA[i] = 0x1a
	}
	if len(m.Signature) > 0 {
		i -= len(m.Signature)
		copy(dAtA[i:], m.Signature)
		i = encodeVarintTypes(dAtA, i, uint64(len(m.Signature)))
		i--
		dAtA[i] = 0x12
	}
	{
		size, err := m.Signer.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintTypes(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0xa
	return len(dAtA) - i, nil
}

func encodeVarintTypes(dAtA []byte, offset int, v uint64) int {
	offset -= sovTypes(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *Transaction) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = m.Signer.Size()
	n += 1 + l + sovTypes(uint64(l))
	l = len(m.Signature)
	if l > 0 {
		n += 1 + l + sovTypes(uint64(l))
	}
	l = len(m.Hash)
	if l > 0 {
		n += 1 + l + sovTypes(uint64(l))
	}
	l = github_com_cosmos_gogoproto_types.SizeOfStdTime(m.Time)
	n += 1 + l + sovTypes(uint64(l))
	if m.Len != 0 {
		n += 1 + sovTypes(uint64(m.Len))
	}
	l = len(m.Body)
	if l > 0 {
		n += 1 + l + sovTypes(uint64(l))
	}
	return n
}

func sovTypes(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozTypes(x uint64) (n int) {
	return sovTypes(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *Transaction) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTypes
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Transaction: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Transaction: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Signer", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTypes
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Signer.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Signature", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthTypes
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Signature = append(m.Signature[:0], dAtA[iNdEx:postIndex]...)
			if m.Signature == nil {
				m.Signature = []byte{}
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Hash", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthTypes
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Hash = append(m.Hash[:0], dAtA[iNdEx:postIndex]...)
			if m.Hash == nil {
				m.Hash = []byte{}
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Time", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTypes
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := github_com_cosmos_gogoproto_types.StdTimeUnmarshal(&m.Time, dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 5:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Len", wireType)
			}
			m.Len = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Len |= uint32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Body", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthTypes
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Body = append(m.Body[:0], dAtA[iNdEx:postIndex]...)
			if m.Body == nil {
				m.Body = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTypes(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthTypes
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipTypes(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowTypes
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthTypes
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupTypes
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthTypes
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthTypes        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowTypes          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupTypes = fmt.Errorf("proto: unexpected end of group")
)
