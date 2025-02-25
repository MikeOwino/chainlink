// Code generated by mockery v2.52.3. DO NOT EDIT.

package mocks

import (
	big "math/big"

	bind "github.com/ethereum/go-ethereum/accounts/abi/bind"

	generated "github.com/smartcontractkit/chainlink/v2/core/gethwrappers/generated"

	keeper_registry_wrapper2_0 "github.com/smartcontractkit/chainlink/v2/core/gethwrappers/generated/keeper_registry_wrapper2_0"

	mock "github.com/stretchr/testify/mock"

	types "github.com/ethereum/go-ethereum/core/types"
)

// Registry is an autogenerated mock type for the Registry type
type Registry struct {
	mock.Mock
}

type Registry_Expecter struct {
	mock *mock.Mock
}

func (_m *Registry) EXPECT() *Registry_Expecter {
	return &Registry_Expecter{mock: &_m.Mock}
}

// GetActiveUpkeepIDs provides a mock function with given fields: opts, startIndex, maxCount
func (_m *Registry) GetActiveUpkeepIDs(opts *bind.CallOpts, startIndex *big.Int, maxCount *big.Int) ([]*big.Int, error) {
	ret := _m.Called(opts, startIndex, maxCount)

	if len(ret) == 0 {
		panic("no return value specified for GetActiveUpkeepIDs")
	}

	var r0 []*big.Int
	var r1 error
	if rf, ok := ret.Get(0).(func(*bind.CallOpts, *big.Int, *big.Int) ([]*big.Int, error)); ok {
		return rf(opts, startIndex, maxCount)
	}
	if rf, ok := ret.Get(0).(func(*bind.CallOpts, *big.Int, *big.Int) []*big.Int); ok {
		r0 = rf(opts, startIndex, maxCount)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*big.Int)
		}
	}

	if rf, ok := ret.Get(1).(func(*bind.CallOpts, *big.Int, *big.Int) error); ok {
		r1 = rf(opts, startIndex, maxCount)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Registry_GetActiveUpkeepIDs_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetActiveUpkeepIDs'
type Registry_GetActiveUpkeepIDs_Call struct {
	*mock.Call
}

// GetActiveUpkeepIDs is a helper method to define mock.On call
//   - opts *bind.CallOpts
//   - startIndex *big.Int
//   - maxCount *big.Int
func (_e *Registry_Expecter) GetActiveUpkeepIDs(opts interface{}, startIndex interface{}, maxCount interface{}) *Registry_GetActiveUpkeepIDs_Call {
	return &Registry_GetActiveUpkeepIDs_Call{Call: _e.mock.On("GetActiveUpkeepIDs", opts, startIndex, maxCount)}
}

func (_c *Registry_GetActiveUpkeepIDs_Call) Run(run func(opts *bind.CallOpts, startIndex *big.Int, maxCount *big.Int)) *Registry_GetActiveUpkeepIDs_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*bind.CallOpts), args[1].(*big.Int), args[2].(*big.Int))
	})
	return _c
}

func (_c *Registry_GetActiveUpkeepIDs_Call) Return(_a0 []*big.Int, _a1 error) *Registry_GetActiveUpkeepIDs_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Registry_GetActiveUpkeepIDs_Call) RunAndReturn(run func(*bind.CallOpts, *big.Int, *big.Int) ([]*big.Int, error)) *Registry_GetActiveUpkeepIDs_Call {
	_c.Call.Return(run)
	return _c
}

// GetState provides a mock function with given fields: opts
func (_m *Registry) GetState(opts *bind.CallOpts) (keeper_registry_wrapper2_0.GetState, error) {
	ret := _m.Called(opts)

	if len(ret) == 0 {
		panic("no return value specified for GetState")
	}

	var r0 keeper_registry_wrapper2_0.GetState
	var r1 error
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) (keeper_registry_wrapper2_0.GetState, error)); ok {
		return rf(opts)
	}
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) keeper_registry_wrapper2_0.GetState); ok {
		r0 = rf(opts)
	} else {
		r0 = ret.Get(0).(keeper_registry_wrapper2_0.GetState)
	}

	if rf, ok := ret.Get(1).(func(*bind.CallOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Registry_GetState_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetState'
type Registry_GetState_Call struct {
	*mock.Call
}

// GetState is a helper method to define mock.On call
//   - opts *bind.CallOpts
func (_e *Registry_Expecter) GetState(opts interface{}) *Registry_GetState_Call {
	return &Registry_GetState_Call{Call: _e.mock.On("GetState", opts)}
}

func (_c *Registry_GetState_Call) Run(run func(opts *bind.CallOpts)) *Registry_GetState_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*bind.CallOpts))
	})
	return _c
}

func (_c *Registry_GetState_Call) Return(_a0 keeper_registry_wrapper2_0.GetState, _a1 error) *Registry_GetState_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Registry_GetState_Call) RunAndReturn(run func(*bind.CallOpts) (keeper_registry_wrapper2_0.GetState, error)) *Registry_GetState_Call {
	_c.Call.Return(run)
	return _c
}

// GetUpkeep provides a mock function with given fields: opts, id
func (_m *Registry) GetUpkeep(opts *bind.CallOpts, id *big.Int) (keeper_registry_wrapper2_0.UpkeepInfo, error) {
	ret := _m.Called(opts, id)

	if len(ret) == 0 {
		panic("no return value specified for GetUpkeep")
	}

	var r0 keeper_registry_wrapper2_0.UpkeepInfo
	var r1 error
	if rf, ok := ret.Get(0).(func(*bind.CallOpts, *big.Int) (keeper_registry_wrapper2_0.UpkeepInfo, error)); ok {
		return rf(opts, id)
	}
	if rf, ok := ret.Get(0).(func(*bind.CallOpts, *big.Int) keeper_registry_wrapper2_0.UpkeepInfo); ok {
		r0 = rf(opts, id)
	} else {
		r0 = ret.Get(0).(keeper_registry_wrapper2_0.UpkeepInfo)
	}

	if rf, ok := ret.Get(1).(func(*bind.CallOpts, *big.Int) error); ok {
		r1 = rf(opts, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Registry_GetUpkeep_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetUpkeep'
type Registry_GetUpkeep_Call struct {
	*mock.Call
}

// GetUpkeep is a helper method to define mock.On call
//   - opts *bind.CallOpts
//   - id *big.Int
func (_e *Registry_Expecter) GetUpkeep(opts interface{}, id interface{}) *Registry_GetUpkeep_Call {
	return &Registry_GetUpkeep_Call{Call: _e.mock.On("GetUpkeep", opts, id)}
}

func (_c *Registry_GetUpkeep_Call) Run(run func(opts *bind.CallOpts, id *big.Int)) *Registry_GetUpkeep_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*bind.CallOpts), args[1].(*big.Int))
	})
	return _c
}

func (_c *Registry_GetUpkeep_Call) Return(_a0 keeper_registry_wrapper2_0.UpkeepInfo, _a1 error) *Registry_GetUpkeep_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Registry_GetUpkeep_Call) RunAndReturn(run func(*bind.CallOpts, *big.Int) (keeper_registry_wrapper2_0.UpkeepInfo, error)) *Registry_GetUpkeep_Call {
	_c.Call.Return(run)
	return _c
}

// ParseLog provides a mock function with given fields: log
func (_m *Registry) ParseLog(log types.Log) (generated.AbigenLog, error) {
	ret := _m.Called(log)

	if len(ret) == 0 {
		panic("no return value specified for ParseLog")
	}

	var r0 generated.AbigenLog
	var r1 error
	if rf, ok := ret.Get(0).(func(types.Log) (generated.AbigenLog, error)); ok {
		return rf(log)
	}
	if rf, ok := ret.Get(0).(func(types.Log) generated.AbigenLog); ok {
		r0 = rf(log)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(generated.AbigenLog)
		}
	}

	if rf, ok := ret.Get(1).(func(types.Log) error); ok {
		r1 = rf(log)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Registry_ParseLog_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ParseLog'
type Registry_ParseLog_Call struct {
	*mock.Call
}

// ParseLog is a helper method to define mock.On call
//   - log types.Log
func (_e *Registry_Expecter) ParseLog(log interface{}) *Registry_ParseLog_Call {
	return &Registry_ParseLog_Call{Call: _e.mock.On("ParseLog", log)}
}

func (_c *Registry_ParseLog_Call) Run(run func(log types.Log)) *Registry_ParseLog_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(types.Log))
	})
	return _c
}

func (_c *Registry_ParseLog_Call) Return(_a0 generated.AbigenLog, _a1 error) *Registry_ParseLog_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Registry_ParseLog_Call) RunAndReturn(run func(types.Log) (generated.AbigenLog, error)) *Registry_ParseLog_Call {
	_c.Call.Return(run)
	return _c
}

// NewRegistry creates a new instance of Registry. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewRegistry(t interface {
	mock.TestingT
	Cleanup(func())
}) *Registry {
	mock := &Registry{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
