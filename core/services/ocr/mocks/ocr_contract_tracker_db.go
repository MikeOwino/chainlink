// Code generated by mockery v2.14.0. DO NOT EDIT.

package mocks

import (
	mock "github.com/stretchr/testify/mock"

	offchainaggregator "github.com/smartcontractkit/libocr/gethwrappers/offchainaggregator"

	pg "github.com/smartcontractkit/chainlink/core/services/pg"
)

// OCRContractTrackerDB is an autogenerated mock type for the OCRContractTrackerDB type
type OCRContractTrackerDB struct {
	mock.Mock
}

// LoadLatestRoundRequested provides a mock function with given fields:
func (_m *OCRContractTrackerDB) LoadLatestRoundRequested() (offchainaggregator.OffchainAggregatorRoundRequested, error) {
	ret := _m.Called()

	var r0 offchainaggregator.OffchainAggregatorRoundRequested
	if rf, ok := ret.Get(0).(func() offchainaggregator.OffchainAggregatorRoundRequested); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(offchainaggregator.OffchainAggregatorRoundRequested)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SaveLatestRoundRequested provides a mock function with given fields: tx, rr
func (_m *OCRContractTrackerDB) SaveLatestRoundRequested(tx pg.Queryer, rr offchainaggregator.OffchainAggregatorRoundRequested) error {
	ret := _m.Called(tx, rr)

	var r0 error
	if rf, ok := ret.Get(0).(func(pg.Queryer, offchainaggregator.OffchainAggregatorRoundRequested) error); ok {
		r0 = rf(tx, rr)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTNewOCRContractTrackerDB interface {
	mock.TestingT
	Cleanup(func())
}

// NewOCRContractTrackerDB creates a new instance of OCRContractTrackerDB. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewOCRContractTrackerDB(t mockConstructorTestingTNewOCRContractTrackerDB) *OCRContractTrackerDB {
	mock := &OCRContractTrackerDB{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
