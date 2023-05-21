package crypto11

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestUlongToBytes(t *testing.T) {
	ulongData := uint(0x33221100ddccbbaa)
	ulongSlice := ulongToBytes(ulongData)

	expected := "AABBCCDD00112233"
	actual := fmt.Sprintf("%X", string(ulongSlice))
	if expected != actual {
		t.Errorf("expected %s != %s", expected, actual)
	}
}

func TestBytesToUlong(t *testing.T) {
	// Build an slice that is longer than the size of a ulong
	extraLongSlice, _ := hex.DecodeString("AABBCCDD00112233AABBCCDD00112233")
	ulongSlice := extraLongSlice[0:8]

	tests := []struct {
		slice    []uint8
		expected uint
	}{
		{ulongSlice[0:0], 0},
		{ulongSlice[0:1], 0xaa},
		{ulongSlice[0:2], 0xbbaa},
		{ulongSlice[0:3], 0xccbbaa},
		{ulongSlice[0:4], 0xddccbbaa},
		{ulongSlice[0:5], 0x00ddccbbaa},
		{ulongSlice[0:6], 0x1100ddccbbaa},
		{ulongSlice[0:7], 0x221100ddccbbaa},
		{ulongSlice[0:8], 0x33221100ddccbbaa},
		{extraLongSlice, 0x33221100ddccbbaa},
	}

	for _, test := range tests {
		got := bytesToUlong(test.slice)
		if test.expected != got {
			t.Errorf("conversion failed: expected 0x%X != 0x%X", test.expected, got)
		}
	}
}
