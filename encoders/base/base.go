// Package base represents the default format for serializing data.
package base

import (
	"bufio"
	"bytes"
	"encoding/pem"
	"fmt"
	"io"
	"strconv"

	"github.com/drand/kyber/encrypt/ibe"
	"github.com/drand/tlock"
)

// Encoder represents the base serializer for the time lock cli.
type Encoder struct{}

// Encode writes the meta data, cipher DEK and cipher text to the output destination.
func (Encoder) Encode(out io.Writer, cipherDEK *ibe.Ciphertext, cipherText []byte, md tlock.Metadata, armor bool) (err error) {
	var b bytes.Buffer
	ww := bufio.NewWriter(&b)

	defer func() {
		ww.Flush()

		if armor {
			block := pem.Block{
				Type:  "TLE ENCRYPTED FILE",
				Bytes: b.Bytes(),
			}
			if err = pem.Encode(out, &block); err != nil {
				err = fmt.Errorf("encoding to PEM: %w", err)
			}
			return
		}

		_, err = io.Copy(out, &b)
	}()

	kyberPoint, err := cipherDEK.U.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal binary: %w", err)
	}

	fmt.Fprintln(ww, strconv.Itoa(int(md.RoundID)))
	fmt.Fprintln(ww, md.ChainHash)

	ww.Write(kyberPoint)
	ww.Write(cipherDEK.V)
	ww.Write(cipherDEK.W)
	ww.Write(cipherText)

	return nil
}

// Decode reads the encrypted data into its different parts.
func (Encoder) Decode(in io.Reader) (tlock.CipherInfo, error) {
	data, err := io.ReadAll(in)
	if err != nil {
		return tlock.CipherInfo{}, fmt.Errorf("failed to read the data from source: %w", err)
	}

	rr := bufio.NewReader(bytes.NewReader(data))
	if string(data[:5]) == "-----" {
		var block *pem.Block
		if block, _ = pem.Decode(data); block == nil {
			return tlock.CipherInfo{}, fmt.Errorf("decoding PEM: %s", "block is nil")
		}

		rr = bufio.NewReader(bytes.NewReader(block.Bytes))
	}

	roundIDStr, err := readHeaderLine(rr)
	if err != nil {
		return tlock.CipherInfo{}, fmt.Errorf("failed to read roundID: %w", err)
	}

	roundID, err := strconv.Atoi(roundIDStr)
	if err != nil {
		return tlock.CipherInfo{}, fmt.Errorf("failed to convert round: %w", err)
	}

	chainHash, err := readHeaderLine(rr)
	if err != nil {
		return tlock.CipherInfo{}, fmt.Errorf("failed to read chain hash: %w", err)
	}

	kyberPoint, err := readPayloadBytes(rr, 48)
	if err != nil {
		return tlock.CipherInfo{}, fmt.Errorf("failed to read kyber point: %w", err)
	}

	cipherV, err := readPayloadBytes(rr, 32)
	if err != nil {
		return tlock.CipherInfo{}, fmt.Errorf("failed to read cipher v: %w", err)
	}

	cipherW, err := readPayloadBytes(rr, 32)
	if err != nil {
		return tlock.CipherInfo{}, fmt.Errorf("failed to read cipher w: %w", err)
	}

	cipherData, err := readPayloadBytes(rr, 0)
	if err != nil {
		return tlock.CipherInfo{}, fmt.Errorf("failed to read cipher text w: %w", err)
	}

	ci := tlock.CipherInfo{
		Metadata: tlock.Metadata{
			RoundID:   uint64(roundID),
			ChainHash: chainHash,
		},
		CipherDEK: tlock.CipherDEK{
			KyberPoint: kyberPoint,
			CipherV:    cipherV,
			CipherW:    cipherW,
		},
		CipherData: cipherData,
	}

	return ci, nil
}

// =============================================================================

// readPayloadBytes reads the section of the payload.
func readPayloadBytes(rr *bufio.Reader, len int) ([]byte, error) {
	if len == 0 {
		len = rr.Buffered()
	}

	data := make([]byte, len)
	if _, err := rr.Read(data); err != nil {
		return nil, err
	}

	return data, nil
}

// readHeaderLine reads a line of header information.
func readHeaderLine(rr *bufio.Reader) (string, error) {
	text, err := rr.ReadString('\n')
	if err != nil {
		return "", err
	}

	return text[:len(text)-1], nil
}
