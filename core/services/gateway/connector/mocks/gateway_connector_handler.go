// Code generated by mockery v2.52.3. DO NOT EDIT.

package mocks

import (
	api "github.com/smartcontractkit/chainlink/v2/core/services/gateway/api"

	context "context"

	mock "github.com/stretchr/testify/mock"
)

// GatewayConnectorHandler is an autogenerated mock type for the GatewayConnectorHandler type
type GatewayConnectorHandler struct {
	mock.Mock
}

type GatewayConnectorHandler_Expecter struct {
	mock *mock.Mock
}

func (_m *GatewayConnectorHandler) EXPECT() *GatewayConnectorHandler_Expecter {
	return &GatewayConnectorHandler_Expecter{mock: &_m.Mock}
}

// Close provides a mock function with no fields
func (_m *GatewayConnectorHandler) Close() error {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Close")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GatewayConnectorHandler_Close_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Close'
type GatewayConnectorHandler_Close_Call struct {
	*mock.Call
}

// Close is a helper method to define mock.On call
func (_e *GatewayConnectorHandler_Expecter) Close() *GatewayConnectorHandler_Close_Call {
	return &GatewayConnectorHandler_Close_Call{Call: _e.mock.On("Close")}
}

func (_c *GatewayConnectorHandler_Close_Call) Run(run func()) *GatewayConnectorHandler_Close_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *GatewayConnectorHandler_Close_Call) Return(_a0 error) *GatewayConnectorHandler_Close_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *GatewayConnectorHandler_Close_Call) RunAndReturn(run func() error) *GatewayConnectorHandler_Close_Call {
	_c.Call.Return(run)
	return _c
}

// HandleGatewayMessage provides a mock function with given fields: ctx, gatewayId, msg
func (_m *GatewayConnectorHandler) HandleGatewayMessage(ctx context.Context, gatewayId string, msg *api.Message) {
	_m.Called(ctx, gatewayId, msg)
}

// GatewayConnectorHandler_HandleGatewayMessage_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HandleGatewayMessage'
type GatewayConnectorHandler_HandleGatewayMessage_Call struct {
	*mock.Call
}

// HandleGatewayMessage is a helper method to define mock.On call
//   - ctx context.Context
//   - gatewayId string
//   - msg *api.Message
func (_e *GatewayConnectorHandler_Expecter) HandleGatewayMessage(ctx interface{}, gatewayId interface{}, msg interface{}) *GatewayConnectorHandler_HandleGatewayMessage_Call {
	return &GatewayConnectorHandler_HandleGatewayMessage_Call{Call: _e.mock.On("HandleGatewayMessage", ctx, gatewayId, msg)}
}

func (_c *GatewayConnectorHandler_HandleGatewayMessage_Call) Run(run func(ctx context.Context, gatewayId string, msg *api.Message)) *GatewayConnectorHandler_HandleGatewayMessage_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(*api.Message))
	})
	return _c
}

func (_c *GatewayConnectorHandler_HandleGatewayMessage_Call) Return() *GatewayConnectorHandler_HandleGatewayMessage_Call {
	_c.Call.Return()
	return _c
}

func (_c *GatewayConnectorHandler_HandleGatewayMessage_Call) RunAndReturn(run func(context.Context, string, *api.Message)) *GatewayConnectorHandler_HandleGatewayMessage_Call {
	_c.Run(run)
	return _c
}

// Start provides a mock function with given fields: _a0
func (_m *GatewayConnectorHandler) Start(_a0 context.Context) error {
	ret := _m.Called(_a0)

	if len(ret) == 0 {
		panic("no return value specified for Start")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GatewayConnectorHandler_Start_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Start'
type GatewayConnectorHandler_Start_Call struct {
	*mock.Call
}

// Start is a helper method to define mock.On call
//   - _a0 context.Context
func (_e *GatewayConnectorHandler_Expecter) Start(_a0 interface{}) *GatewayConnectorHandler_Start_Call {
	return &GatewayConnectorHandler_Start_Call{Call: _e.mock.On("Start", _a0)}
}

func (_c *GatewayConnectorHandler_Start_Call) Run(run func(_a0 context.Context)) *GatewayConnectorHandler_Start_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *GatewayConnectorHandler_Start_Call) Return(_a0 error) *GatewayConnectorHandler_Start_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *GatewayConnectorHandler_Start_Call) RunAndReturn(run func(context.Context) error) *GatewayConnectorHandler_Start_Call {
	_c.Call.Return(run)
	return _c
}

// NewGatewayConnectorHandler creates a new instance of GatewayConnectorHandler. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewGatewayConnectorHandler(t interface {
	mock.TestingT
	Cleanup(func())
}) *GatewayConnectorHandler {
	mock := &GatewayConnectorHandler{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
