// Code generated by mockery v2.52.3. DO NOT EDIT.

package telemetry

import (
	commontypes "github.com/smartcontractkit/libocr/commontypes"
	mock "github.com/stretchr/testify/mock"

	synchronization "github.com/smartcontractkit/chainlink/v2/core/services/synchronization"
)

// MockMonitoringEndpointGenerator is an autogenerated mock type for the MonitoringEndpointGenerator type
type MockMonitoringEndpointGenerator struct {
	mock.Mock
}

type MockMonitoringEndpointGenerator_Expecter struct {
	mock *mock.Mock
}

func (_m *MockMonitoringEndpointGenerator) EXPECT() *MockMonitoringEndpointGenerator_Expecter {
	return &MockMonitoringEndpointGenerator_Expecter{mock: &_m.Mock}
}

// GenMonitoringEndpoint provides a mock function with given fields: network, chainID, contractID, telemType
func (_m *MockMonitoringEndpointGenerator) GenMonitoringEndpoint(network string, chainID string, contractID string, telemType synchronization.TelemetryType) commontypes.MonitoringEndpoint {
	ret := _m.Called(network, chainID, contractID, telemType)

	if len(ret) == 0 {
		panic("no return value specified for GenMonitoringEndpoint")
	}

	var r0 commontypes.MonitoringEndpoint
	if rf, ok := ret.Get(0).(func(string, string, string, synchronization.TelemetryType) commontypes.MonitoringEndpoint); ok {
		r0 = rf(network, chainID, contractID, telemType)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(commontypes.MonitoringEndpoint)
		}
	}

	return r0
}

// MockMonitoringEndpointGenerator_GenMonitoringEndpoint_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GenMonitoringEndpoint'
type MockMonitoringEndpointGenerator_GenMonitoringEndpoint_Call struct {
	*mock.Call
}

// GenMonitoringEndpoint is a helper method to define mock.On call
//   - network string
//   - chainID string
//   - contractID string
//   - telemType synchronization.TelemetryType
func (_e *MockMonitoringEndpointGenerator_Expecter) GenMonitoringEndpoint(network interface{}, chainID interface{}, contractID interface{}, telemType interface{}) *MockMonitoringEndpointGenerator_GenMonitoringEndpoint_Call {
	return &MockMonitoringEndpointGenerator_GenMonitoringEndpoint_Call{Call: _e.mock.On("GenMonitoringEndpoint", network, chainID, contractID, telemType)}
}

func (_c *MockMonitoringEndpointGenerator_GenMonitoringEndpoint_Call) Run(run func(network string, chainID string, contractID string, telemType synchronization.TelemetryType)) *MockMonitoringEndpointGenerator_GenMonitoringEndpoint_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string), args[2].(string), args[3].(synchronization.TelemetryType))
	})
	return _c
}

func (_c *MockMonitoringEndpointGenerator_GenMonitoringEndpoint_Call) Return(_a0 commontypes.MonitoringEndpoint) *MockMonitoringEndpointGenerator_GenMonitoringEndpoint_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMonitoringEndpointGenerator_GenMonitoringEndpoint_Call) RunAndReturn(run func(string, string, string, synchronization.TelemetryType) commontypes.MonitoringEndpoint) *MockMonitoringEndpointGenerator_GenMonitoringEndpoint_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockMonitoringEndpointGenerator creates a new instance of MockMonitoringEndpointGenerator. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockMonitoringEndpointGenerator(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockMonitoringEndpointGenerator {
	mock := &MockMonitoringEndpointGenerator{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
