// Code generated by mockery v2.52.3. DO NOT EDIT.

package pricegetter

import (
	context "context"
	big "math/big"

	ccip "github.com/smartcontractkit/chainlink-common/pkg/types/ccip"

	mock "github.com/stretchr/testify/mock"
)

// MockPriceGetter is an autogenerated mock type for the PriceGetter type
type MockPriceGetter struct {
	mock.Mock
}

type MockPriceGetter_Expecter struct {
	mock *mock.Mock
}

func (_m *MockPriceGetter) EXPECT() *MockPriceGetter_Expecter {
	return &MockPriceGetter_Expecter{mock: &_m.Mock}
}

// Close provides a mock function with no fields
func (_m *MockPriceGetter) Close() error {
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

// MockPriceGetter_Close_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Close'
type MockPriceGetter_Close_Call struct {
	*mock.Call
}

// Close is a helper method to define mock.On call
func (_e *MockPriceGetter_Expecter) Close() *MockPriceGetter_Close_Call {
	return &MockPriceGetter_Close_Call{Call: _e.mock.On("Close")}
}

func (_c *MockPriceGetter_Close_Call) Run(run func()) *MockPriceGetter_Close_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockPriceGetter_Close_Call) Return(_a0 error) *MockPriceGetter_Close_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockPriceGetter_Close_Call) RunAndReturn(run func() error) *MockPriceGetter_Close_Call {
	_c.Call.Return(run)
	return _c
}

// FilterConfiguredTokens provides a mock function with given fields: ctx, tokens
func (_m *MockPriceGetter) FilterConfiguredTokens(ctx context.Context, tokens []ccip.Address) ([]ccip.Address, []ccip.Address, error) {
	ret := _m.Called(ctx, tokens)

	if len(ret) == 0 {
		panic("no return value specified for FilterConfiguredTokens")
	}

	var r0 []ccip.Address
	var r1 []ccip.Address
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, []ccip.Address) ([]ccip.Address, []ccip.Address, error)); ok {
		return rf(ctx, tokens)
	}
	if rf, ok := ret.Get(0).(func(context.Context, []ccip.Address) []ccip.Address); ok {
		r0 = rf(ctx, tokens)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]ccip.Address)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, []ccip.Address) []ccip.Address); ok {
		r1 = rf(ctx, tokens)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).([]ccip.Address)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, []ccip.Address) error); ok {
		r2 = rf(ctx, tokens)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockPriceGetter_FilterConfiguredTokens_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FilterConfiguredTokens'
type MockPriceGetter_FilterConfiguredTokens_Call struct {
	*mock.Call
}

// FilterConfiguredTokens is a helper method to define mock.On call
//   - ctx context.Context
//   - tokens []ccip.Address
func (_e *MockPriceGetter_Expecter) FilterConfiguredTokens(ctx interface{}, tokens interface{}) *MockPriceGetter_FilterConfiguredTokens_Call {
	return &MockPriceGetter_FilterConfiguredTokens_Call{Call: _e.mock.On("FilterConfiguredTokens", ctx, tokens)}
}

func (_c *MockPriceGetter_FilterConfiguredTokens_Call) Run(run func(ctx context.Context, tokens []ccip.Address)) *MockPriceGetter_FilterConfiguredTokens_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].([]ccip.Address))
	})
	return _c
}

func (_c *MockPriceGetter_FilterConfiguredTokens_Call) Return(configured []ccip.Address, unconfigured []ccip.Address, err error) *MockPriceGetter_FilterConfiguredTokens_Call {
	_c.Call.Return(configured, unconfigured, err)
	return _c
}

func (_c *MockPriceGetter_FilterConfiguredTokens_Call) RunAndReturn(run func(context.Context, []ccip.Address) ([]ccip.Address, []ccip.Address, error)) *MockPriceGetter_FilterConfiguredTokens_Call {
	_c.Call.Return(run)
	return _c
}

// TokenPricesUSD provides a mock function with given fields: ctx, tokens
func (_m *MockPriceGetter) TokenPricesUSD(ctx context.Context, tokens []ccip.Address) (map[ccip.Address]*big.Int, error) {
	ret := _m.Called(ctx, tokens)

	if len(ret) == 0 {
		panic("no return value specified for TokenPricesUSD")
	}

	var r0 map[ccip.Address]*big.Int
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, []ccip.Address) (map[ccip.Address]*big.Int, error)); ok {
		return rf(ctx, tokens)
	}
	if rf, ok := ret.Get(0).(func(context.Context, []ccip.Address) map[ccip.Address]*big.Int); ok {
		r0 = rf(ctx, tokens)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[ccip.Address]*big.Int)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, []ccip.Address) error); ok {
		r1 = rf(ctx, tokens)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockPriceGetter_TokenPricesUSD_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'TokenPricesUSD'
type MockPriceGetter_TokenPricesUSD_Call struct {
	*mock.Call
}

// TokenPricesUSD is a helper method to define mock.On call
//   - ctx context.Context
//   - tokens []ccip.Address
func (_e *MockPriceGetter_Expecter) TokenPricesUSD(ctx interface{}, tokens interface{}) *MockPriceGetter_TokenPricesUSD_Call {
	return &MockPriceGetter_TokenPricesUSD_Call{Call: _e.mock.On("TokenPricesUSD", ctx, tokens)}
}

func (_c *MockPriceGetter_TokenPricesUSD_Call) Run(run func(ctx context.Context, tokens []ccip.Address)) *MockPriceGetter_TokenPricesUSD_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].([]ccip.Address))
	})
	return _c
}

func (_c *MockPriceGetter_TokenPricesUSD_Call) Return(_a0 map[ccip.Address]*big.Int, _a1 error) *MockPriceGetter_TokenPricesUSD_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockPriceGetter_TokenPricesUSD_Call) RunAndReturn(run func(context.Context, []ccip.Address) (map[ccip.Address]*big.Int, error)) *MockPriceGetter_TokenPricesUSD_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockPriceGetter creates a new instance of MockPriceGetter. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockPriceGetter(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockPriceGetter {
	mock := &MockPriceGetter{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
