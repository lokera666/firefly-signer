// Code generated by mockery v1.0.0. DO NOT EDIT.

package ethsignermocks

import (
	context "context"

	ethsigner "github.com/hyperledger/firefly-signer/pkg/ethsigner"
	ethtypes "github.com/hyperledger/firefly-signer/pkg/ethtypes"

	mock "github.com/stretchr/testify/mock"
)

// Wallet is an autogenerated mock type for the Wallet type
type Wallet struct {
	mock.Mock
}

// Close provides a mock function with given fields:
func (_m *Wallet) Close() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetAccounts provides a mock function with given fields: ctx
func (_m *Wallet) GetAccounts(ctx context.Context) ([]*ethtypes.Address0xHex, error) {
	ret := _m.Called(ctx)

	var r0 []*ethtypes.Address0xHex
	if rf, ok := ret.Get(0).(func(context.Context) []*ethtypes.Address0xHex); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*ethtypes.Address0xHex)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Initialize provides a mock function with given fields: ctx
func (_m *Wallet) Initialize(ctx context.Context) error {
	ret := _m.Called(ctx)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context) error); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Refresh provides a mock function with given fields: ctx
func (_m *Wallet) Refresh(ctx context.Context) error {
	ret := _m.Called(ctx)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context) error); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Sign provides a mock function with given fields: ctx, addr, tx, chainID
func (_m *Wallet) Sign(ctx context.Context, addr *ethtypes.Address0xHex, tx *ethsigner.Transaction, chainID int64) ([]byte, error) {
	ret := _m.Called(ctx, addr, tx, chainID)

	var r0 []byte
	if rf, ok := ret.Get(0).(func(context.Context, *ethtypes.Address0xHex, *ethsigner.Transaction, int64) []byte); ok {
		r0 = rf(ctx, addr, tx, chainID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *ethtypes.Address0xHex, *ethsigner.Transaction, int64) error); ok {
		r1 = rf(ctx, addr, tx, chainID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}