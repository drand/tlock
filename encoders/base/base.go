// Package base implements the Encoder/Decoder interfaces for the tlock package.
package base

import (
	"bufio"
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/drand/tlock"
)

// Encoder knows how to encode/decode cipher information.
type Encoder struct{}

// Encode writes the cipher info to the output destination. If armor is true,
// the encoding is done with PEM encoding.
func (Encoder) Encode(out io.Writer, cipherInfo tlock.CipherInfo, armor bool) (err error) {
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

	roundNumber := strconv.FormatInt(int64(cipherInfo.MetaData.RoundNumber), 10)
	fmt.Fprintf(ww, "%010d", len(roundNumber))
	fmt.Fprint(ww, roundNumber)

	fmt.Fprintf(ww, "%010d", len(cipherInfo.MetaData.ChainHash))
	fmt.Fprint(ww, cipherInfo.MetaData.ChainHash)

	ww.Write(cipherInfo.CipherDEK.KyberPoint)
	ww.Write(cipherInfo.CipherDEK.CipherV)
	ww.Write(cipherInfo.CipherDEK.CipherW)

	fmt.Fprintf(ww, "%010d", len(cipherInfo.CipherData))
	ww.Write(cipherInfo.CipherData)

	return nil
}

// Decode reads input source for the cipherInfo. If an io.EOF is returned, there
// is no more cipherInfo to decode. If io.ErrUnexpectedEOF is returned, the last
// cipherInfo has been decoded from the source.
func (Encoder) Decode(in io.Reader) (tlock.CipherInfo, error) {

	// if string(unknown[:5]) == "-----" {
	// 	var block *pem.Block
	// 	if block, _ = pem.Decode(data); block == nil {
	// 		return tlock.CipherInfo{}, fmt.Errorf("decoding PEM: %s", "block is nil")
	// 	}

	// 	rr = bufio.NewReader(bytes.NewReader(block.Bytes))
	// }

	metaData, err := readMetaData(in)
	if err != nil {
		return tlock.CipherInfo{}, fmt.Errorf("round number: %w", err)
	}

	cipherDEK, err := readCipherDEK(in)
	if err != nil {
		return tlock.CipherInfo{}, fmt.Errorf("cipher dek: %w", err)
	}

	cipherData, err := readCipherData(in)
	if err != nil && err != io.ErrUnexpectedEOF {
		return tlock.CipherInfo{}, fmt.Errorf("cipher data: %w", err)
	}

	ci := tlock.CipherInfo{
		MetaData:   metaData,
		CipherDEK:  cipherDEK,
		CipherData: cipherData,
	}

	if errors.Is(err, io.ErrUnexpectedEOF) {
		return ci, io.ErrUnexpectedEOF
	}

	return ci, nil
}

// =============================================================================

// readMetaData reads the metadata section from the input source.
func readMetaData(in io.Reader) (tlock.MetaData, error) {

	// ------------------------------------------------------------

	str, err := readBytes(in, 10)
	if err != nil {
		return tlock.MetaData{}, fmt.Errorf("read round string: %w", err)
	}

	len, err := strconv.Atoi(string(str))
	if err != nil {
		return tlock.MetaData{}, fmt.Errorf("convert round length: %w", err)
	}

	roundStr, err := readBytes(in, len)
	if err != nil {
		return tlock.MetaData{}, fmt.Errorf("read round: %w", err)
	}

	roundNumber, err := strconv.Atoi(string(roundStr))
	if err != nil {
		return tlock.MetaData{}, fmt.Errorf("convert round: %w", err)
	}

	// ------------------------------------------------------------

	str, err = readBytes(in, 10)
	if err != nil {
		return tlock.MetaData{}, fmt.Errorf("read chain hash string: %w", err)
	}

	len, err = strconv.Atoi(string(str))
	if err != nil {
		return tlock.MetaData{}, fmt.Errorf("convert chain hash length: %w", err)
	}

	chainHash, err := readBytes(in, len)
	if err != nil {
		return tlock.MetaData{}, fmt.Errorf("read chain hash: %w", err)
	}

	// ------------------------------------------------------------

	md := tlock.MetaData{
		RoundNumber: uint64(roundNumber),
		ChainHash:   string(chainHash),
	}

	return md, nil
}

// readCipherDEK reads the cipher dek section from the input source.
func readCipherDEK(in io.Reader) (tlock.CipherDEK, error) {
	kyberPoint, err := readBytes(in, 48)
	if err != nil {
		return tlock.CipherDEK{}, fmt.Errorf("read kyber point: %w", err)
	}

	cipherV, err := readBytes(in, 32)
	if err != nil {
		return tlock.CipherDEK{}, fmt.Errorf("read cipher v: %w", err)
	}

	cipherW, err := readBytes(in, 32)
	if err != nil {
		return tlock.CipherDEK{}, fmt.Errorf("read cipher w: %w", err)
	}

	cd := tlock.CipherDEK{
		KyberPoint: kyberPoint,
		CipherV:    cipherV,
		CipherW:    cipherW,
	}

	return cd, nil
}

// readCipherData reads the cipher data from the input source.
func readCipherData(in io.Reader) ([]byte, error) {
	str, err := readBytes(in, 10)
	if err != nil {
		return nil, fmt.Errorf("read cipher data string: %w", err)
	}

	len, err := strconv.Atoi(string(str))
	if err != nil {
		return nil, fmt.Errorf("convert cipher data length: %w", err)
	}

	return readBytes(in, len)
}

// readBytes reads the specified number of bytes from the reader.
func readBytes(in io.Reader, length int) ([]byte, error) {
	data := make([]byte, length)
	n, err := io.ReadFull(in, data)

	switch {
	case err == io.EOF:
		return []byte{}, io.EOF

	case err == io.ErrUnexpectedEOF:
		return data[:n], io.ErrUnexpectedEOF

	case err != nil:
		return []byte{}, err
	}

	return data[:n], nil
}
