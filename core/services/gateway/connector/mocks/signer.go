// Code generated by mockery v2.52.3. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// Signer is an autogenerated mock type for the Signer type
type Signer struct {
	mock.Mock
}

type Signer_Expecter struct {
	mock *mock.Mock
}

func (_m *Signer) EXPECT() *Signer_Expecter {
	return &Signer_Expecter{mock: &_m.Mock}
}

// Sign provides a mock function with given fields: data
func (_m *Signer) Sign(data ...[]byte) ([]byte, error) {
	_va := make([]interface{}, len(data))
	for _i := range data {
		_va[_i] = data[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for Sign")
	}

	var r0 []byte
	var r1 error
	if rf, ok := ret.Get(0).(func(...[]byte) ([]byte, error)); ok {
		return rf(data...)
	}
	if rf, ok := ret.Get(0).(func(...[]byte) []byte); ok {
		r0 = rf(data...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func(...[]byte) error); ok {
		r1 = rf(data...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Signer_Sign_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Sign'
type Signer_Sign_Call struct {
	*mock.Call
}

// Sign is a helper method to define mock.On call
//   - data ...[]byte
func (_e *Signer_Expecter) Sign(data ...interface{}) *Signer_Sign_Call {
	return &Signer_Sign_Call{Call: _e.mock.On("Sign",
		append([]interface{}{}, data...)...)}
}

func (_c *Signer_Sign_Call) Run(run func(data ...[]byte)) *Signer_Sign_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([][]byte, len(args)-0)
		for i, a := range args[0:] {
			if a != nil {
				variadicArgs[i] = a.([]byte)
			}
		}
		run(variadicArgs...)
	})
	return _c
}

func (_c *Signer_Sign_Call) Return(_a0 []byte, _a1 error) *Signer_Sign_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Signer_Sign_Call) RunAndReturn(run func(...[]byte) ([]byte, error)) *Signer_Sign_Call {
	_c.Call.Return(run)
	return _c
}

// NewSigner creates a new instance of Signer. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewSigner(t interface {
	mock.TestingT
	Cleanup(func())
}) *Signer {
	mock := &Signer{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
