package main

import (
	"bytes"
	"fmt"
	"testing"
)

func Test_intEncode(t *testing.T) {
	tests := []struct {
		input uint64
		want  []byte
	}{
		{1677685200, []byte{252, 208, 113, 255, 99}},
		{5, []byte{5}},
		{255, []byte{251, 255, 0}},
		{15266267, []byte{252, 219, 241, 232, 0}},
		{1595431050, []byte{252, 138, 88, 24, 95}},
		{4641203, []byte{252, 179, 209, 70, 0}},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("test-%d", tt.input), func(t *testing.T) {
			got := intEncode(tt.input)
			t.Log("got", got, "for", tt.input)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("intEncode() = %v, want %v", got, tt.want)
			}
			if dec, err := intDecode(bytes.NewReader(got)); err <= 0 || dec != tt.input {
				t.Errorf("intDecode() = %v, err %v", dec, err)
			}
		})
	}
}

func Test_intDecode(t *testing.T) {
	tests := []struct {
		want  uint64
		input []byte
	}{
		{1677685200, []byte{252, 208, 113, 255, 99}},
		{5, []byte{5}},
		{5, []byte{5, 0, 0}},
		{5, []byte{5, 0}},
		{255, []byte{251, 255, 0}},
		{255, []byte{251, 255}},
		{15266267, []byte{252, 219, 241, 232, 0, 0, 0}},
		{1595431050, []byte{252, 138, 88, 24, 95}},
		{4641203, []byte{252, 179, 209, 70, 0}},
		{4641203, []byte{252, 179, 209, 70}},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("test-%d", tt.input), func(t *testing.T) {
			got, n := intDecode(bytes.NewReader(tt.input))
			t.Log("got", got, "for", tt.input)
			if got != tt.want || n <= 0 {
				t.Errorf("intDecode() = %v, err %v", got, n)
			}
		})
	}
}
