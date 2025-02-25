// Code generated by mockery v2.52.3. DO NOT EDIT.

package mocks

import (
	mock "github.com/stretchr/testify/mock"

	url "net/url"
)

// ConnectionInitiator is an autogenerated mock type for the ConnectionInitiator type
type ConnectionInitiator struct {
	mock.Mock
}

type ConnectionInitiator_Expecter struct {
	mock *mock.Mock
}

func (_m *ConnectionInitiator) EXPECT() *ConnectionInitiator_Expecter {
	return &ConnectionInitiator_Expecter{mock: &_m.Mock}
}

// ChallengeResponse provides a mock function with given fields: _a0, challenge
func (_m *ConnectionInitiator) ChallengeResponse(_a0 *url.URL, challenge []byte) ([]byte, error) {
	ret := _m.Called(_a0, challenge)

	if len(ret) == 0 {
		panic("no return value specified for ChallengeResponse")
	}

	var r0 []byte
	var r1 error
	if rf, ok := ret.Get(0).(func(*url.URL, []byte) ([]byte, error)); ok {
		return rf(_a0, challenge)
	}
	if rf, ok := ret.Get(0).(func(*url.URL, []byte) []byte); ok {
		r0 = rf(_a0, challenge)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func(*url.URL, []byte) error); ok {
		r1 = rf(_a0, challenge)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ConnectionInitiator_ChallengeResponse_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ChallengeResponse'
type ConnectionInitiator_ChallengeResponse_Call struct {
	*mock.Call
}

// ChallengeResponse is a helper method to define mock.On call
//   - _a0 *url.URL
//   - challenge []byte
func (_e *ConnectionInitiator_Expecter) ChallengeResponse(_a0 interface{}, challenge interface{}) *ConnectionInitiator_ChallengeResponse_Call {
	return &ConnectionInitiator_ChallengeResponse_Call{Call: _e.mock.On("ChallengeResponse", _a0, challenge)}
}

func (_c *ConnectionInitiator_ChallengeResponse_Call) Run(run func(_a0 *url.URL, challenge []byte)) *ConnectionInitiator_ChallengeResponse_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*url.URL), args[1].([]byte))
	})
	return _c
}

func (_c *ConnectionInitiator_ChallengeResponse_Call) Return(_a0 []byte, _a1 error) *ConnectionInitiator_ChallengeResponse_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ConnectionInitiator_ChallengeResponse_Call) RunAndReturn(run func(*url.URL, []byte) ([]byte, error)) *ConnectionInitiator_ChallengeResponse_Call {
	_c.Call.Return(run)
	return _c
}

// NewAuthHeader provides a mock function with given fields: _a0
func (_m *ConnectionInitiator) NewAuthHeader(_a0 *url.URL) ([]byte, error) {
	ret := _m.Called(_a0)

	if len(ret) == 0 {
		panic("no return value specified for NewAuthHeader")
	}

	var r0 []byte
	var r1 error
	if rf, ok := ret.Get(0).(func(*url.URL) ([]byte, error)); ok {
		return rf(_a0)
	}
	if rf, ok := ret.Get(0).(func(*url.URL) []byte); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func(*url.URL) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ConnectionInitiator_NewAuthHeader_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'NewAuthHeader'
type ConnectionInitiator_NewAuthHeader_Call struct {
	*mock.Call
}

// NewAuthHeader is a helper method to define mock.On call
//   - _a0 *url.URL
func (_e *ConnectionInitiator_Expecter) NewAuthHeader(_a0 interface{}) *ConnectionInitiator_NewAuthHeader_Call {
	return &ConnectionInitiator_NewAuthHeader_Call{Call: _e.mock.On("NewAuthHeader", _a0)}
}

func (_c *ConnectionInitiator_NewAuthHeader_Call) Run(run func(_a0 *url.URL)) *ConnectionInitiator_NewAuthHeader_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*url.URL))
	})
	return _c
}

func (_c *ConnectionInitiator_NewAuthHeader_Call) Return(_a0 []byte, _a1 error) *ConnectionInitiator_NewAuthHeader_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ConnectionInitiator_NewAuthHeader_Call) RunAndReturn(run func(*url.URL) ([]byte, error)) *ConnectionInitiator_NewAuthHeader_Call {
	_c.Call.Return(run)
	return _c
}

// NewConnectionInitiator creates a new instance of ConnectionInitiator. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewConnectionInitiator(t interface {
	mock.TestingT
	Cleanup(func())
}) *ConnectionInitiator {
	mock := &ConnectionInitiator{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
