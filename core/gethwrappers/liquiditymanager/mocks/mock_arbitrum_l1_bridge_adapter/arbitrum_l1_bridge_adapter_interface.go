// Code generated by mockery v2.52.3. DO NOT EDIT.

package mock_arbitrum_l1_bridge_adapter

import (
	big "math/big"

	arbitrum_l1_bridge_adapter "github.com/smartcontractkit/chainlink/v2/core/gethwrappers/liquiditymanager/generated/arbitrum_l1_bridge_adapter"

	bind "github.com/ethereum/go-ethereum/accounts/abi/bind"

	common "github.com/ethereum/go-ethereum/common"

	mock "github.com/stretchr/testify/mock"

	types "github.com/ethereum/go-ethereum/core/types"
)

// ArbitrumL1BridgeAdapterInterface is an autogenerated mock type for the ArbitrumL1BridgeAdapterInterface type
type ArbitrumL1BridgeAdapterInterface struct {
	mock.Mock
}

type ArbitrumL1BridgeAdapterInterface_Expecter struct {
	mock *mock.Mock
}

func (_m *ArbitrumL1BridgeAdapterInterface) EXPECT() *ArbitrumL1BridgeAdapterInterface_Expecter {
	return &ArbitrumL1BridgeAdapterInterface_Expecter{mock: &_m.Mock}
}

// Address provides a mock function with no fields
func (_m *ArbitrumL1BridgeAdapterInterface) Address() common.Address {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Address")
	}

	var r0 common.Address
	if rf, ok := ret.Get(0).(func() common.Address); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(common.Address)
		}
	}

	return r0
}

// ArbitrumL1BridgeAdapterInterface_Address_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Address'
type ArbitrumL1BridgeAdapterInterface_Address_Call struct {
	*mock.Call
}

// Address is a helper method to define mock.On call
func (_e *ArbitrumL1BridgeAdapterInterface_Expecter) Address() *ArbitrumL1BridgeAdapterInterface_Address_Call {
	return &ArbitrumL1BridgeAdapterInterface_Address_Call{Call: _e.mock.On("Address")}
}

func (_c *ArbitrumL1BridgeAdapterInterface_Address_Call) Run(run func()) *ArbitrumL1BridgeAdapterInterface_Address_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *ArbitrumL1BridgeAdapterInterface_Address_Call) Return(_a0 common.Address) *ArbitrumL1BridgeAdapterInterface_Address_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ArbitrumL1BridgeAdapterInterface_Address_Call) RunAndReturn(run func() common.Address) *ArbitrumL1BridgeAdapterInterface_Address_Call {
	_c.Call.Return(run)
	return _c
}

// ExposeArbitrumFinalizationPayload provides a mock function with given fields: opts, payload
func (_m *ArbitrumL1BridgeAdapterInterface) ExposeArbitrumFinalizationPayload(opts *bind.CallOpts, payload arbitrum_l1_bridge_adapter.ArbitrumL1BridgeAdapterArbitrumFinalizationPayload) error {
	ret := _m.Called(opts, payload)

	if len(ret) == 0 {
		panic("no return value specified for ExposeArbitrumFinalizationPayload")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*bind.CallOpts, arbitrum_l1_bridge_adapter.ArbitrumL1BridgeAdapterArbitrumFinalizationPayload) error); ok {
		r0 = rf(opts, payload)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ArbitrumL1BridgeAdapterInterface_ExposeArbitrumFinalizationPayload_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ExposeArbitrumFinalizationPayload'
type ArbitrumL1BridgeAdapterInterface_ExposeArbitrumFinalizationPayload_Call struct {
	*mock.Call
}

// ExposeArbitrumFinalizationPayload is a helper method to define mock.On call
//   - opts *bind.CallOpts
//   - payload arbitrum_l1_bridge_adapter.ArbitrumL1BridgeAdapterArbitrumFinalizationPayload
func (_e *ArbitrumL1BridgeAdapterInterface_Expecter) ExposeArbitrumFinalizationPayload(opts interface{}, payload interface{}) *ArbitrumL1BridgeAdapterInterface_ExposeArbitrumFinalizationPayload_Call {
	return &ArbitrumL1BridgeAdapterInterface_ExposeArbitrumFinalizationPayload_Call{Call: _e.mock.On("ExposeArbitrumFinalizationPayload", opts, payload)}
}

func (_c *ArbitrumL1BridgeAdapterInterface_ExposeArbitrumFinalizationPayload_Call) Run(run func(opts *bind.CallOpts, payload arbitrum_l1_bridge_adapter.ArbitrumL1BridgeAdapterArbitrumFinalizationPayload)) *ArbitrumL1BridgeAdapterInterface_ExposeArbitrumFinalizationPayload_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*bind.CallOpts), args[1].(arbitrum_l1_bridge_adapter.ArbitrumL1BridgeAdapterArbitrumFinalizationPayload))
	})
	return _c
}

func (_c *ArbitrumL1BridgeAdapterInterface_ExposeArbitrumFinalizationPayload_Call) Return(_a0 error) *ArbitrumL1BridgeAdapterInterface_ExposeArbitrumFinalizationPayload_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ArbitrumL1BridgeAdapterInterface_ExposeArbitrumFinalizationPayload_Call) RunAndReturn(run func(*bind.CallOpts, arbitrum_l1_bridge_adapter.ArbitrumL1BridgeAdapterArbitrumFinalizationPayload) error) *ArbitrumL1BridgeAdapterInterface_ExposeArbitrumFinalizationPayload_Call {
	_c.Call.Return(run)
	return _c
}

// ExposeSendERC20Params provides a mock function with given fields: opts, params
func (_m *ArbitrumL1BridgeAdapterInterface) ExposeSendERC20Params(opts *bind.CallOpts, params arbitrum_l1_bridge_adapter.ArbitrumL1BridgeAdapterSendERC20Params) error {
	ret := _m.Called(opts, params)

	if len(ret) == 0 {
		panic("no return value specified for ExposeSendERC20Params")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*bind.CallOpts, arbitrum_l1_bridge_adapter.ArbitrumL1BridgeAdapterSendERC20Params) error); ok {
		r0 = rf(opts, params)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ArbitrumL1BridgeAdapterInterface_ExposeSendERC20Params_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ExposeSendERC20Params'
type ArbitrumL1BridgeAdapterInterface_ExposeSendERC20Params_Call struct {
	*mock.Call
}

// ExposeSendERC20Params is a helper method to define mock.On call
//   - opts *bind.CallOpts
//   - params arbitrum_l1_bridge_adapter.ArbitrumL1BridgeAdapterSendERC20Params
func (_e *ArbitrumL1BridgeAdapterInterface_Expecter) ExposeSendERC20Params(opts interface{}, params interface{}) *ArbitrumL1BridgeAdapterInterface_ExposeSendERC20Params_Call {
	return &ArbitrumL1BridgeAdapterInterface_ExposeSendERC20Params_Call{Call: _e.mock.On("ExposeSendERC20Params", opts, params)}
}

func (_c *ArbitrumL1BridgeAdapterInterface_ExposeSendERC20Params_Call) Run(run func(opts *bind.CallOpts, params arbitrum_l1_bridge_adapter.ArbitrumL1BridgeAdapterSendERC20Params)) *ArbitrumL1BridgeAdapterInterface_ExposeSendERC20Params_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*bind.CallOpts), args[1].(arbitrum_l1_bridge_adapter.ArbitrumL1BridgeAdapterSendERC20Params))
	})
	return _c
}

func (_c *ArbitrumL1BridgeAdapterInterface_ExposeSendERC20Params_Call) Return(_a0 error) *ArbitrumL1BridgeAdapterInterface_ExposeSendERC20Params_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ArbitrumL1BridgeAdapterInterface_ExposeSendERC20Params_Call) RunAndReturn(run func(*bind.CallOpts, arbitrum_l1_bridge_adapter.ArbitrumL1BridgeAdapterSendERC20Params) error) *ArbitrumL1BridgeAdapterInterface_ExposeSendERC20Params_Call {
	_c.Call.Return(run)
	return _c
}

// FinalizeWithdrawERC20 provides a mock function with given fields: opts, arg0, arg1, arbitrumFinalizationPayload
func (_m *ArbitrumL1BridgeAdapterInterface) FinalizeWithdrawERC20(opts *bind.TransactOpts, arg0 common.Address, arg1 common.Address, arbitrumFinalizationPayload []byte) (*types.Transaction, error) {
	ret := _m.Called(opts, arg0, arg1, arbitrumFinalizationPayload)

	if len(ret) == 0 {
		panic("no return value specified for FinalizeWithdrawERC20")
	}

	var r0 *types.Transaction
	var r1 error
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts, common.Address, common.Address, []byte) (*types.Transaction, error)); ok {
		return rf(opts, arg0, arg1, arbitrumFinalizationPayload)
	}
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts, common.Address, common.Address, []byte) *types.Transaction); ok {
		r0 = rf(opts, arg0, arg1, arbitrumFinalizationPayload)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.Transaction)
		}
	}

	if rf, ok := ret.Get(1).(func(*bind.TransactOpts, common.Address, common.Address, []byte) error); ok {
		r1 = rf(opts, arg0, arg1, arbitrumFinalizationPayload)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ArbitrumL1BridgeAdapterInterface_FinalizeWithdrawERC20_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FinalizeWithdrawERC20'
type ArbitrumL1BridgeAdapterInterface_FinalizeWithdrawERC20_Call struct {
	*mock.Call
}

// FinalizeWithdrawERC20 is a helper method to define mock.On call
//   - opts *bind.TransactOpts
//   - arg0 common.Address
//   - arg1 common.Address
//   - arbitrumFinalizationPayload []byte
func (_e *ArbitrumL1BridgeAdapterInterface_Expecter) FinalizeWithdrawERC20(opts interface{}, arg0 interface{}, arg1 interface{}, arbitrumFinalizationPayload interface{}) *ArbitrumL1BridgeAdapterInterface_FinalizeWithdrawERC20_Call {
	return &ArbitrumL1BridgeAdapterInterface_FinalizeWithdrawERC20_Call{Call: _e.mock.On("FinalizeWithdrawERC20", opts, arg0, arg1, arbitrumFinalizationPayload)}
}

func (_c *ArbitrumL1BridgeAdapterInterface_FinalizeWithdrawERC20_Call) Run(run func(opts *bind.TransactOpts, arg0 common.Address, arg1 common.Address, arbitrumFinalizationPayload []byte)) *ArbitrumL1BridgeAdapterInterface_FinalizeWithdrawERC20_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*bind.TransactOpts), args[1].(common.Address), args[2].(common.Address), args[3].([]byte))
	})
	return _c
}

func (_c *ArbitrumL1BridgeAdapterInterface_FinalizeWithdrawERC20_Call) Return(_a0 *types.Transaction, _a1 error) *ArbitrumL1BridgeAdapterInterface_FinalizeWithdrawERC20_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ArbitrumL1BridgeAdapterInterface_FinalizeWithdrawERC20_Call) RunAndReturn(run func(*bind.TransactOpts, common.Address, common.Address, []byte) (*types.Transaction, error)) *ArbitrumL1BridgeAdapterInterface_FinalizeWithdrawERC20_Call {
	_c.Call.Return(run)
	return _c
}

// GetBridgeFeeInNative provides a mock function with given fields: opts
func (_m *ArbitrumL1BridgeAdapterInterface) GetBridgeFeeInNative(opts *bind.CallOpts) (*big.Int, error) {
	ret := _m.Called(opts)

	if len(ret) == 0 {
		panic("no return value specified for GetBridgeFeeInNative")
	}

	var r0 *big.Int
	var r1 error
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) (*big.Int, error)); ok {
		return rf(opts)
	}
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) *big.Int); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*big.Int)
		}
	}

	if rf, ok := ret.Get(1).(func(*bind.CallOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ArbitrumL1BridgeAdapterInterface_GetBridgeFeeInNative_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetBridgeFeeInNative'
type ArbitrumL1BridgeAdapterInterface_GetBridgeFeeInNative_Call struct {
	*mock.Call
}

// GetBridgeFeeInNative is a helper method to define mock.On call
//   - opts *bind.CallOpts
func (_e *ArbitrumL1BridgeAdapterInterface_Expecter) GetBridgeFeeInNative(opts interface{}) *ArbitrumL1BridgeAdapterInterface_GetBridgeFeeInNative_Call {
	return &ArbitrumL1BridgeAdapterInterface_GetBridgeFeeInNative_Call{Call: _e.mock.On("GetBridgeFeeInNative", opts)}
}

func (_c *ArbitrumL1BridgeAdapterInterface_GetBridgeFeeInNative_Call) Run(run func(opts *bind.CallOpts)) *ArbitrumL1BridgeAdapterInterface_GetBridgeFeeInNative_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*bind.CallOpts))
	})
	return _c
}

func (_c *ArbitrumL1BridgeAdapterInterface_GetBridgeFeeInNative_Call) Return(_a0 *big.Int, _a1 error) *ArbitrumL1BridgeAdapterInterface_GetBridgeFeeInNative_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ArbitrumL1BridgeAdapterInterface_GetBridgeFeeInNative_Call) RunAndReturn(run func(*bind.CallOpts) (*big.Int, error)) *ArbitrumL1BridgeAdapterInterface_GetBridgeFeeInNative_Call {
	_c.Call.Return(run)
	return _c
}

// GetL2Token provides a mock function with given fields: opts, l1Token
func (_m *ArbitrumL1BridgeAdapterInterface) GetL2Token(opts *bind.CallOpts, l1Token common.Address) (common.Address, error) {
	ret := _m.Called(opts, l1Token)

	if len(ret) == 0 {
		panic("no return value specified for GetL2Token")
	}

	var r0 common.Address
	var r1 error
	if rf, ok := ret.Get(0).(func(*bind.CallOpts, common.Address) (common.Address, error)); ok {
		return rf(opts, l1Token)
	}
	if rf, ok := ret.Get(0).(func(*bind.CallOpts, common.Address) common.Address); ok {
		r0 = rf(opts, l1Token)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(common.Address)
		}
	}

	if rf, ok := ret.Get(1).(func(*bind.CallOpts, common.Address) error); ok {
		r1 = rf(opts, l1Token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ArbitrumL1BridgeAdapterInterface_GetL2Token_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetL2Token'
type ArbitrumL1BridgeAdapterInterface_GetL2Token_Call struct {
	*mock.Call
}

// GetL2Token is a helper method to define mock.On call
//   - opts *bind.CallOpts
//   - l1Token common.Address
func (_e *ArbitrumL1BridgeAdapterInterface_Expecter) GetL2Token(opts interface{}, l1Token interface{}) *ArbitrumL1BridgeAdapterInterface_GetL2Token_Call {
	return &ArbitrumL1BridgeAdapterInterface_GetL2Token_Call{Call: _e.mock.On("GetL2Token", opts, l1Token)}
}

func (_c *ArbitrumL1BridgeAdapterInterface_GetL2Token_Call) Run(run func(opts *bind.CallOpts, l1Token common.Address)) *ArbitrumL1BridgeAdapterInterface_GetL2Token_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*bind.CallOpts), args[1].(common.Address))
	})
	return _c
}

func (_c *ArbitrumL1BridgeAdapterInterface_GetL2Token_Call) Return(_a0 common.Address, _a1 error) *ArbitrumL1BridgeAdapterInterface_GetL2Token_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ArbitrumL1BridgeAdapterInterface_GetL2Token_Call) RunAndReturn(run func(*bind.CallOpts, common.Address) (common.Address, error)) *ArbitrumL1BridgeAdapterInterface_GetL2Token_Call {
	_c.Call.Return(run)
	return _c
}

// SendERC20 provides a mock function with given fields: opts, localToken, arg1, recipient, amount, bridgeSpecificPayload
func (_m *ArbitrumL1BridgeAdapterInterface) SendERC20(opts *bind.TransactOpts, localToken common.Address, arg1 common.Address, recipient common.Address, amount *big.Int, bridgeSpecificPayload []byte) (*types.Transaction, error) {
	ret := _m.Called(opts, localToken, arg1, recipient, amount, bridgeSpecificPayload)

	if len(ret) == 0 {
		panic("no return value specified for SendERC20")
	}

	var r0 *types.Transaction
	var r1 error
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts, common.Address, common.Address, common.Address, *big.Int, []byte) (*types.Transaction, error)); ok {
		return rf(opts, localToken, arg1, recipient, amount, bridgeSpecificPayload)
	}
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts, common.Address, common.Address, common.Address, *big.Int, []byte) *types.Transaction); ok {
		r0 = rf(opts, localToken, arg1, recipient, amount, bridgeSpecificPayload)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.Transaction)
		}
	}

	if rf, ok := ret.Get(1).(func(*bind.TransactOpts, common.Address, common.Address, common.Address, *big.Int, []byte) error); ok {
		r1 = rf(opts, localToken, arg1, recipient, amount, bridgeSpecificPayload)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ArbitrumL1BridgeAdapterInterface_SendERC20_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SendERC20'
type ArbitrumL1BridgeAdapterInterface_SendERC20_Call struct {
	*mock.Call
}

// SendERC20 is a helper method to define mock.On call
//   - opts *bind.TransactOpts
//   - localToken common.Address
//   - arg1 common.Address
//   - recipient common.Address
//   - amount *big.Int
//   - bridgeSpecificPayload []byte
func (_e *ArbitrumL1BridgeAdapterInterface_Expecter) SendERC20(opts interface{}, localToken interface{}, arg1 interface{}, recipient interface{}, amount interface{}, bridgeSpecificPayload interface{}) *ArbitrumL1BridgeAdapterInterface_SendERC20_Call {
	return &ArbitrumL1BridgeAdapterInterface_SendERC20_Call{Call: _e.mock.On("SendERC20", opts, localToken, arg1, recipient, amount, bridgeSpecificPayload)}
}

func (_c *ArbitrumL1BridgeAdapterInterface_SendERC20_Call) Run(run func(opts *bind.TransactOpts, localToken common.Address, arg1 common.Address, recipient common.Address, amount *big.Int, bridgeSpecificPayload []byte)) *ArbitrumL1BridgeAdapterInterface_SendERC20_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*bind.TransactOpts), args[1].(common.Address), args[2].(common.Address), args[3].(common.Address), args[4].(*big.Int), args[5].([]byte))
	})
	return _c
}

func (_c *ArbitrumL1BridgeAdapterInterface_SendERC20_Call) Return(_a0 *types.Transaction, _a1 error) *ArbitrumL1BridgeAdapterInterface_SendERC20_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ArbitrumL1BridgeAdapterInterface_SendERC20_Call) RunAndReturn(run func(*bind.TransactOpts, common.Address, common.Address, common.Address, *big.Int, []byte) (*types.Transaction, error)) *ArbitrumL1BridgeAdapterInterface_SendERC20_Call {
	_c.Call.Return(run)
	return _c
}

// NewArbitrumL1BridgeAdapterInterface creates a new instance of ArbitrumL1BridgeAdapterInterface. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewArbitrumL1BridgeAdapterInterface(t interface {
	mock.TestingT
	Cleanup(func())
}) *ArbitrumL1BridgeAdapterInterface {
	mock := &ArbitrumL1BridgeAdapterInterface{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
