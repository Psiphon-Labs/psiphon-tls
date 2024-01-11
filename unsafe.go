// Code borrowd from https://github.com/quic-go/qtls-go1-20

package tls

import (
	"crypto/tls"
	"reflect"
	"unsafe"
)

func init() {
	if !structsEqual(&tls.ConnectionState{}, &connectionState{}) {
		panic("tls.ConnectionState doesn't match")
	}
	if !structsEqual(&tls.ClientSessionState{}, &clientSessionState{}) {
		panic("tls.ClientSessionState doesn't match")
	}
}

func toConnectionState(c connectionState) ConnectionState {
	return *(*ConnectionState)(unsafe.Pointer(&c))
}

func toClientSessionState(s *clientSessionState) *ClientSessionState {
	return (*ClientSessionState)(unsafe.Pointer(s))
}

func fromClientSessionState(s *ClientSessionState) *clientSessionState {
	return (*clientSessionState)(unsafe.Pointer(s))
}

func structsEqual(a, b interface{}) bool {
	sa := reflect.ValueOf(a).Elem()
	sb := reflect.ValueOf(b).Elem()
	if sa.NumField() != sb.NumField() {
		return false
	}
	for i := 0; i < sa.NumField(); i++ {
		fa := sa.Type().Field(i)
		fb := sb.Type().Field(i)
		if !reflect.DeepEqual(fa.Index, fb.Index) || fa.Name != fb.Name || fa.Anonymous != fb.Anonymous || fa.Offset != fb.Offset || !reflect.DeepEqual(fa.Type, fb.Type) {
			return false
		}
	}
	return true
}
