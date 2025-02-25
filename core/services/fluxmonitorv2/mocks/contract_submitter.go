// Code generated by mockery v2.52.3. DO NOT EDIT.

package mocks

import (
	context "context"
	big "math/big"

	mock "github.com/stretchr/testify/mock"
)

// ContractSubmitter is an autogenerated mock type for the ContractSubmitter type
type ContractSubmitter struct {
	mock.Mock
}

type ContractSubmitter_Expecter struct {
	mock *mock.Mock
}

func (_m *ContractSubmitter) EXPECT() *ContractSubmitter_Expecter {
	return &ContractSubmitter_Expecter{mock: &_m.Mock}
}

// Submit provides a mock function with given fields: ctx, roundID, submission, idempotencyKey
func (_m *ContractSubmitter) Submit(ctx context.Context, roundID *big.Int, submission *big.Int, idempotencyKey *string) error {
	ret := _m.Called(ctx, roundID, submission, idempotencyKey)

	if len(ret) == 0 {
		panic("no return value specified for Submit")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *big.Int, *big.Int, *string) error); ok {
		r0 = rf(ctx, roundID, submission, idempotencyKey)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ContractSubmitter_Submit_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Submit'
type ContractSubmitter_Submit_Call struct {
	*mock.Call
}

// Submit is a helper method to define mock.On call
//   - ctx context.Context
//   - roundID *big.Int
//   - submission *big.Int
//   - idempotencyKey *string
func (_e *ContractSubmitter_Expecter) Submit(ctx interface{}, roundID interface{}, submission interface{}, idempotencyKey interface{}) *ContractSubmitter_Submit_Call {
	return &ContractSubmitter_Submit_Call{Call: _e.mock.On("Submit", ctx, roundID, submission, idempotencyKey)}
}

func (_c *ContractSubmitter_Submit_Call) Run(run func(ctx context.Context, roundID *big.Int, submission *big.Int, idempotencyKey *string)) *ContractSubmitter_Submit_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*big.Int), args[2].(*big.Int), args[3].(*string))
	})
	return _c
}

func (_c *ContractSubmitter_Submit_Call) Return(_a0 error) *ContractSubmitter_Submit_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ContractSubmitter_Submit_Call) RunAndReturn(run func(context.Context, *big.Int, *big.Int, *string) error) *ContractSubmitter_Submit_Call {
	_c.Call.Return(run)
	return _c
}

// NewContractSubmitter creates a new instance of ContractSubmitter. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewContractSubmitter(t interface {
	mock.TestingT
	Cleanup(func())
}) *ContractSubmitter {
	mock := &ContractSubmitter{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
