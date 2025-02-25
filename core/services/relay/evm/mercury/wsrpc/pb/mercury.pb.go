// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.5
// 	protoc        v5.29.3
// source: mercury.proto

package pb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type TransmitRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Payload       []byte                 `protobuf:"bytes,1,opt,name=payload,proto3" json:"payload,omitempty"`
	ReportFormat  uint32                 `protobuf:"varint,2,opt,name=reportFormat,proto3" json:"reportFormat,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *TransmitRequest) Reset() {
	*x = TransmitRequest{}
	mi := &file_mercury_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TransmitRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TransmitRequest) ProtoMessage() {}

func (x *TransmitRequest) ProtoReflect() protoreflect.Message {
	mi := &file_mercury_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TransmitRequest.ProtoReflect.Descriptor instead.
func (*TransmitRequest) Descriptor() ([]byte, []int) {
	return file_mercury_proto_rawDescGZIP(), []int{0}
}

func (x *TransmitRequest) GetPayload() []byte {
	if x != nil {
		return x.Payload
	}
	return nil
}

func (x *TransmitRequest) GetReportFormat() uint32 {
	if x != nil {
		return x.ReportFormat
	}
	return 0
}

type TransmitResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Code          int32                  `protobuf:"varint,1,opt,name=code,proto3" json:"code,omitempty"`
	Error         string                 `protobuf:"bytes,2,opt,name=error,proto3" json:"error,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *TransmitResponse) Reset() {
	*x = TransmitResponse{}
	mi := &file_mercury_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TransmitResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TransmitResponse) ProtoMessage() {}

func (x *TransmitResponse) ProtoReflect() protoreflect.Message {
	mi := &file_mercury_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TransmitResponse.ProtoReflect.Descriptor instead.
func (*TransmitResponse) Descriptor() ([]byte, []int) {
	return file_mercury_proto_rawDescGZIP(), []int{1}
}

func (x *TransmitResponse) GetCode() int32 {
	if x != nil {
		return x.Code
	}
	return 0
}

func (x *TransmitResponse) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

type LatestReportRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	FeedId        []byte                 `protobuf:"bytes,1,opt,name=feedId,proto3" json:"feedId,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LatestReportRequest) Reset() {
	*x = LatestReportRequest{}
	mi := &file_mercury_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LatestReportRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LatestReportRequest) ProtoMessage() {}

func (x *LatestReportRequest) ProtoReflect() protoreflect.Message {
	mi := &file_mercury_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LatestReportRequest.ProtoReflect.Descriptor instead.
func (*LatestReportRequest) Descriptor() ([]byte, []int) {
	return file_mercury_proto_rawDescGZIP(), []int{2}
}

func (x *LatestReportRequest) GetFeedId() []byte {
	if x != nil {
		return x.FeedId
	}
	return nil
}

type LatestReportResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Error         string                 `protobuf:"bytes,1,opt,name=error,proto3" json:"error,omitempty"`
	Report        *Report                `protobuf:"bytes,2,opt,name=report,proto3" json:"report,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LatestReportResponse) Reset() {
	*x = LatestReportResponse{}
	mi := &file_mercury_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LatestReportResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LatestReportResponse) ProtoMessage() {}

func (x *LatestReportResponse) ProtoReflect() protoreflect.Message {
	mi := &file_mercury_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LatestReportResponse.ProtoReflect.Descriptor instead.
func (*LatestReportResponse) Descriptor() ([]byte, []int) {
	return file_mercury_proto_rawDescGZIP(), []int{3}
}

func (x *LatestReportResponse) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

func (x *LatestReportResponse) GetReport() *Report {
	if x != nil {
		return x.Report
	}
	return nil
}

type Report struct {
	state                 protoimpl.MessageState `protogen:"open.v1"`
	FeedId                []byte                 `protobuf:"bytes,1,opt,name=feedId,proto3" json:"feedId,omitempty"`
	Price                 []byte                 `protobuf:"bytes,2,opt,name=price,proto3" json:"price,omitempty"`
	Payload               []byte                 `protobuf:"bytes,3,opt,name=payload,proto3" json:"payload,omitempty"`
	ValidFromBlockNumber  int64                  `protobuf:"varint,4,opt,name=validFromBlockNumber,proto3" json:"validFromBlockNumber,omitempty"`
	CurrentBlockNumber    int64                  `protobuf:"varint,5,opt,name=currentBlockNumber,proto3" json:"currentBlockNumber,omitempty"`
	CurrentBlockHash      []byte                 `protobuf:"bytes,6,opt,name=currentBlockHash,proto3" json:"currentBlockHash,omitempty"`
	CurrentBlockTimestamp uint64                 `protobuf:"varint,7,opt,name=currentBlockTimestamp,proto3" json:"currentBlockTimestamp,omitempty"`
	ObservationsTimestamp int64                  `protobuf:"varint,8,opt,name=observationsTimestamp,proto3" json:"observationsTimestamp,omitempty"`
	ConfigDigest          []byte                 `protobuf:"bytes,9,opt,name=configDigest,proto3" json:"configDigest,omitempty"`
	Epoch                 uint32                 `protobuf:"varint,10,opt,name=epoch,proto3" json:"epoch,omitempty"`
	Round                 uint32                 `protobuf:"varint,11,opt,name=round,proto3" json:"round,omitempty"`
	OperatorName          string                 `protobuf:"bytes,12,opt,name=operatorName,proto3" json:"operatorName,omitempty"`
	TransmittingOperator  []byte                 `protobuf:"bytes,13,opt,name=transmittingOperator,proto3" json:"transmittingOperator,omitempty"`
	CreatedAt             *Timestamp             `protobuf:"bytes,14,opt,name=createdAt,proto3" json:"createdAt,omitempty"`
	unknownFields         protoimpl.UnknownFields
	sizeCache             protoimpl.SizeCache
}

func (x *Report) Reset() {
	*x = Report{}
	mi := &file_mercury_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Report) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Report) ProtoMessage() {}

func (x *Report) ProtoReflect() protoreflect.Message {
	mi := &file_mercury_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Report.ProtoReflect.Descriptor instead.
func (*Report) Descriptor() ([]byte, []int) {
	return file_mercury_proto_rawDescGZIP(), []int{4}
}

func (x *Report) GetFeedId() []byte {
	if x != nil {
		return x.FeedId
	}
	return nil
}

func (x *Report) GetPrice() []byte {
	if x != nil {
		return x.Price
	}
	return nil
}

func (x *Report) GetPayload() []byte {
	if x != nil {
		return x.Payload
	}
	return nil
}

func (x *Report) GetValidFromBlockNumber() int64 {
	if x != nil {
		return x.ValidFromBlockNumber
	}
	return 0
}

func (x *Report) GetCurrentBlockNumber() int64 {
	if x != nil {
		return x.CurrentBlockNumber
	}
	return 0
}

func (x *Report) GetCurrentBlockHash() []byte {
	if x != nil {
		return x.CurrentBlockHash
	}
	return nil
}

func (x *Report) GetCurrentBlockTimestamp() uint64 {
	if x != nil {
		return x.CurrentBlockTimestamp
	}
	return 0
}

func (x *Report) GetObservationsTimestamp() int64 {
	if x != nil {
		return x.ObservationsTimestamp
	}
	return 0
}

func (x *Report) GetConfigDigest() []byte {
	if x != nil {
		return x.ConfigDigest
	}
	return nil
}

func (x *Report) GetEpoch() uint32 {
	if x != nil {
		return x.Epoch
	}
	return 0
}

func (x *Report) GetRound() uint32 {
	if x != nil {
		return x.Round
	}
	return 0
}

func (x *Report) GetOperatorName() string {
	if x != nil {
		return x.OperatorName
	}
	return ""
}

func (x *Report) GetTransmittingOperator() []byte {
	if x != nil {
		return x.TransmittingOperator
	}
	return nil
}

func (x *Report) GetCreatedAt() *Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

// Taken from: https://github.com/protocolbuffers/protobuf/blob/main/src/google/protobuf/timestamp.proto
type Timestamp struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Represents seconds of UTC time since Unix epoch
	// 1970-01-01T00:00:00Z. Must be from 0001-01-01T00:00:00Z to
	// 9999-12-31T23:59:59Z inclusive.
	Seconds int64 `protobuf:"varint,1,opt,name=seconds,proto3" json:"seconds,omitempty"`
	// Non-negative fractions of a second at nanosecond resolution. Negative
	// second values with fractions must still have non-negative nanos values
	// that count forward in time. Must be from 0 to 999,999,999
	// inclusive.
	Nanos         int32 `protobuf:"varint,2,opt,name=nanos,proto3" json:"nanos,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Timestamp) Reset() {
	*x = Timestamp{}
	mi := &file_mercury_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Timestamp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Timestamp) ProtoMessage() {}

func (x *Timestamp) ProtoReflect() protoreflect.Message {
	mi := &file_mercury_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Timestamp.ProtoReflect.Descriptor instead.
func (*Timestamp) Descriptor() ([]byte, []int) {
	return file_mercury_proto_rawDescGZIP(), []int{5}
}

func (x *Timestamp) GetSeconds() int64 {
	if x != nil {
		return x.Seconds
	}
	return 0
}

func (x *Timestamp) GetNanos() int32 {
	if x != nil {
		return x.Nanos
	}
	return 0
}

var File_mercury_proto protoreflect.FileDescriptor

var file_mercury_proto_rawDesc = string([]byte{
	0x0a, 0x0d, 0x6d, 0x65, 0x72, 0x63, 0x75, 0x72, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x02, 0x70, 0x62, 0x22, 0x4f, 0x0a, 0x0f, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x6d, 0x69, 0x74, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
	0x12, 0x22, 0x0a, 0x0c, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0c, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x46, 0x6f,
	0x72, 0x6d, 0x61, 0x74, 0x22, 0x3c, 0x0a, 0x10, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x6d, 0x69, 0x74,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x63, 0x6f, 0x64, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x12, 0x14, 0x0a, 0x05,
	0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x72, 0x72,
	0x6f, 0x72, 0x22, 0x2d, 0x0a, 0x13, 0x4c, 0x61, 0x74, 0x65, 0x73, 0x74, 0x52, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x66, 0x65, 0x65,
	0x64, 0x49, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x66, 0x65, 0x65, 0x64, 0x49,
	0x64, 0x22, 0x50, 0x0a, 0x14, 0x4c, 0x61, 0x74, 0x65, 0x73, 0x74, 0x52, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x72, 0x72,
	0x6f, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x12,
	0x22, 0x0a, 0x06, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x0a, 0x2e, 0x70, 0x62, 0x2e, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x52, 0x06, 0x72, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x22, 0xa1, 0x04, 0x0a, 0x06, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x16,
	0x0a, 0x06, 0x66, 0x65, 0x65, 0x64, 0x49, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06,
	0x66, 0x65, 0x65, 0x64, 0x49, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x72, 0x69, 0x63, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x70, 0x72, 0x69, 0x63, 0x65, 0x12, 0x18, 0x0a, 0x07,
	0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x70,
	0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x32, 0x0a, 0x14, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x46,
	0x72, 0x6f, 0x6d, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x03, 0x52, 0x14, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x46, 0x72, 0x6f, 0x6d, 0x42,
	0x6c, 0x6f, 0x63, 0x6b, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x2e, 0x0a, 0x12, 0x63, 0x75,
	0x72, 0x72, 0x65, 0x6e, 0x74, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x12, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x42,
	0x6c, 0x6f, 0x63, 0x6b, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x2a, 0x0a, 0x10, 0x63, 0x75,
	0x72, 0x72, 0x65, 0x6e, 0x74, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x48, 0x61, 0x73, 0x68, 0x18, 0x06,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x10, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x42, 0x6c, 0x6f,
	0x63, 0x6b, 0x48, 0x61, 0x73, 0x68, 0x12, 0x34, 0x0a, 0x15, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6e,
	0x74, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18,
	0x07, 0x20, 0x01, 0x28, 0x04, 0x52, 0x15, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x42, 0x6c,
	0x6f, 0x63, 0x6b, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x12, 0x34, 0x0a, 0x15,
	0x6f, 0x62, 0x73, 0x65, 0x72, 0x76, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x54, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x08, 0x20, 0x01, 0x28, 0x03, 0x52, 0x15, 0x6f, 0x62, 0x73,
	0x65, 0x72, 0x76, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x12, 0x22, 0x0a, 0x0c, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x44, 0x69, 0x67, 0x65,
	0x73, 0x74, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0c, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x44, 0x69, 0x67, 0x65, 0x73, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x70, 0x6f, 0x63, 0x68, 0x18,
	0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x65, 0x70, 0x6f, 0x63, 0x68, 0x12, 0x14, 0x0a, 0x05,
	0x72, 0x6f, 0x75, 0x6e, 0x64, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x72, 0x6f, 0x75,
	0x6e, 0x64, 0x12, 0x22, 0x0a, 0x0c, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x4e, 0x61,
	0x6d, 0x65, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74,
	0x6f, 0x72, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x32, 0x0a, 0x14, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x6d,
	0x69, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x18, 0x0d,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x14, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x6d, 0x69, 0x74, 0x74, 0x69,
	0x6e, 0x67, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x12, 0x2b, 0x0a, 0x09, 0x63, 0x72,
	0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e,
	0x70, 0x62, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x63, 0x72,
	0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x22, 0x3b, 0x0a, 0x09, 0x54, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x12, 0x18, 0x0a, 0x07, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x73, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x07, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x73, 0x12, 0x14,
	0x0a, 0x05, 0x6e, 0x61, 0x6e, 0x6f, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x05, 0x52, 0x05, 0x6e,
	0x61, 0x6e, 0x6f, 0x73, 0x32, 0x83, 0x01, 0x0a, 0x07, 0x4d, 0x65, 0x72, 0x63, 0x75, 0x72, 0x79,
	0x12, 0x35, 0x0a, 0x08, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x6d, 0x69, 0x74, 0x12, 0x13, 0x2e, 0x70,
	0x62, 0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x6d, 0x69, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x14, 0x2e, 0x70, 0x62, 0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x6d, 0x69, 0x74, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x41, 0x0a, 0x0c, 0x4c, 0x61, 0x74, 0x65, 0x73,
	0x74, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x17, 0x2e, 0x70, 0x62, 0x2e, 0x4c, 0x61, 0x74,
	0x65, 0x73, 0x74, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x18, 0x2e, 0x70, 0x62, 0x2e, 0x4c, 0x61, 0x74, 0x65, 0x73, 0x74, 0x52, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x4e, 0x5a, 0x4c, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x6d, 0x61, 0x72, 0x74, 0x63, 0x6f,
	0x6e, 0x74, 0x72, 0x61, 0x63, 0x74, 0x6b, 0x69, 0x74, 0x2f, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x6c,
	0x69, 0x6e, 0x6b, 0x2f, 0x76, 0x32, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2f,
	0x72, 0x65, 0x6c, 0x61, 0x79, 0x2f, 0x65, 0x76, 0x6d, 0x2f, 0x6d, 0x65, 0x72, 0x63, 0x75, 0x72,
	0x79, 0x2f, 0x77, 0x73, 0x72, 0x70, 0x63, 0x2f, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
})

var (
	file_mercury_proto_rawDescOnce sync.Once
	file_mercury_proto_rawDescData []byte
)

func file_mercury_proto_rawDescGZIP() []byte {
	file_mercury_proto_rawDescOnce.Do(func() {
		file_mercury_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_mercury_proto_rawDesc), len(file_mercury_proto_rawDesc)))
	})
	return file_mercury_proto_rawDescData
}

var file_mercury_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_mercury_proto_goTypes = []any{
	(*TransmitRequest)(nil),      // 0: pb.TransmitRequest
	(*TransmitResponse)(nil),     // 1: pb.TransmitResponse
	(*LatestReportRequest)(nil),  // 2: pb.LatestReportRequest
	(*LatestReportResponse)(nil), // 3: pb.LatestReportResponse
	(*Report)(nil),               // 4: pb.Report
	(*Timestamp)(nil),            // 5: pb.Timestamp
}
var file_mercury_proto_depIdxs = []int32{
	4, // 0: pb.LatestReportResponse.report:type_name -> pb.Report
	5, // 1: pb.Report.createdAt:type_name -> pb.Timestamp
	0, // 2: pb.Mercury.Transmit:input_type -> pb.TransmitRequest
	2, // 3: pb.Mercury.LatestReport:input_type -> pb.LatestReportRequest
	1, // 4: pb.Mercury.Transmit:output_type -> pb.TransmitResponse
	3, // 5: pb.Mercury.LatestReport:output_type -> pb.LatestReportResponse
	4, // [4:6] is the sub-list for method output_type
	2, // [2:4] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_mercury_proto_init() }
func file_mercury_proto_init() {
	if File_mercury_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_mercury_proto_rawDesc), len(file_mercury_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_mercury_proto_goTypes,
		DependencyIndexes: file_mercury_proto_depIdxs,
		MessageInfos:      file_mercury_proto_msgTypes,
	}.Build()
	File_mercury_proto = out.File
	file_mercury_proto_goTypes = nil
	file_mercury_proto_depIdxs = nil
}
