package main

import (
	"encoding/binary"
	"io"
	"log/slog"
	"math"
)

// intEncode re-implements the bincode format for uint64 values
func intEncode(u uint64) []byte {
	buf := make([]byte, 1, binary.MaxVarintLen64)
	switch {
	case u < 251:
		buf[0] = byte(u)
	case u < math.MaxInt16:
		buf[0] = byte(251)
		buf = binary.LittleEndian.AppendUint16(buf, uint16(u))
	case u < math.MaxInt32:
		buf[0] = byte(252)
		buf = binary.LittleEndian.AppendUint32(buf, uint32(u))
	case u < math.MaxInt64:
		buf[0] = byte(253)
		buf = binary.LittleEndian.AppendUint64(buf, u)
	default:
		// 254 is meant for u128, but we don't support 128 bit integers here.
		buf[0] = byte(254)
	}

	return buf
}

func intDecode(r io.Reader) (uint64, int) {
	buf := make([]byte, 1)
	i, err := r.Read(buf)
	if err != nil || i != 1 {
		slog.Error("intDecode error", "error", err, "read", i)
		return 0, -1
	}
	u := buf[0]
	switch {
	case int(u) < 251:
		return uint64(u), 1
	case u == byte(251):
		data := make([]byte, 2)
		i, err = r.Read(data)
		if err != nil || i <= 0 {
			slog.Error("read data error", "error", err, "read", i)
			return 0, -1
		}
		return uint64(binary.LittleEndian.Uint16(data)), 1 + 2
	case u == byte(252):
		data := make([]byte, 4)
		i, err = r.Read(data)
		if err != nil || i <= 0 {
			slog.Error("read data error", "error", err, "read", i)
			return 0, -1
		}
		return uint64(binary.LittleEndian.Uint32(data)), 1 + 4
	case u == byte(253):
		data := make([]byte, 8)
		i, err = r.Read(data)
		if err != nil || i <= 0 {
			slog.Error("read data error", "error", err, "read", i)
			return 0, -1
		}
		return uint64(binary.LittleEndian.Uint64(data)), 1 + 8
	case u == byte(254):
		slog.Error("u128 are unsupported")
		return 0, -1

	}
	return 0, -1
}
