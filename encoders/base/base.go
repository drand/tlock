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

// pemType represents the block marker for PEM encoding.
const pemType = "TLE ENCRYPTED FILE"

// These constants define size values for encoding/decoding.
const (
	chunkSize = 64 * 1024

	maxUint64Len     = 20
	maxUint64LenVerb = "%020d"
	maxInt64Len      = 10
	maxInt64LenVerb  = "%010d"

	kyberPointLen = 48
	cipherVLen    = 32
	cipherWLen    = 32
)

// =============================================================================

// Encoder knows how to encode cipher information.
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
				Type:  pemType,
				Bytes: b.Bytes(),
			}
			if err = pem.Encode(out, &block); err != nil {
				err = fmt.Errorf("encoding to PEM: %w", err)
			}
			return
		}

		_, err = io.Copy(out, &b)
	}()

	roundNumber := strconv.FormatUint(cipherInfo.MetaData.RoundNumber, 10)
	fmt.Fprintf(ww, maxUint64LenVerb, len(roundNumber))
	fmt.Fprint(ww, roundNumber)

	fmt.Fprintf(ww, maxInt64LenVerb, len(cipherInfo.MetaData.ChainHash))
	fmt.Fprint(ww, cipherInfo.MetaData.ChainHash)

	ww.Write(cipherInfo.CipherDEK.KyberPoint)
	ww.Write(cipherInfo.CipherDEK.CipherV)
	ww.Write(cipherInfo.CipherDEK.CipherW)

	fmt.Fprintf(ww, maxInt64LenVerb, len(cipherInfo.CipherData))
	ww.Write(cipherInfo.CipherData)

	return nil
}

// Decoder knows how to decode cipher information.
type Decoder struct{}

// Decode reads input source for the cipherInfo. If an io.EOF is returned, there
// is no more cipherInfo to decode. If io.ErrUnexpectedEOF is returned, the last
// cipherInfo has been decoded from the source.
func (Decoder) Decode(in io.Reader, armor bool) (tlock.CipherInfo, error) {
	if armor {
		var err error
		in, err = readPEM(in)
		if err != nil {
			return tlock.CipherInfo{}, fmt.Errorf("read pem: %w", err)
		}
	}

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

// readPEM reads the next PEM section in the input source.
func readPEM(in io.Reader) (io.Reader, error) {

	// Read the header for this PEM section.
	const pemBegin = "-----BEGIN " + pemType + "-----\n"
	hdr := make([]byte, len(pemBegin))
	if _, err := io.ReadFull(in, hdr); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	// Read the next chunk of data.
	data := make([]byte, chunkSize)
	n, err := io.ReadFull(in, data)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("read data: %w", err)
	}

	// If we read the remaining data from the input source, we have everything.
	// If not, we need to find the end of this PEM section. We don't know the
	// length, so we need to end the END marker.
	if n == len(data) {
		b := make([]byte, 1)
		for {

			// Read in one byte at a time.
			if _, err := io.ReadFull(in, b); err != nil {
				return nil, fmt.Errorf("read final data: %w", err)
			}

			// Write that byte to the data buffer.
			data = append(data, b[0])

			// If we found the beginning of the END marker.
			if b[0] == byte('-') {
				const pemEnd = "----END " + pemType + "-----\n"
				end := make([]byte, len(pemEnd))
				if _, err := io.ReadFull(in, end); err != nil {
					return nil, fmt.Errorf("read end: %w", err)
				}

				// Write the remaining bytes to the buffer.
				data = append(data, end...)

				break
			}
		}
	}

	// Appened the header and data together.
	pemData := make([]byte, len(hdr)+len(data))
	copy(pemData, hdr)
	copy(pemData[len(hdr):], data)

	// Encode the PEM block.
	var block *pem.Block
	if block, _ = pem.Decode(pemData); block == nil {
		return nil, errors.New("block nil")
	}

	// The caller needs a reader to process the data.
	return bytes.NewReader(block.Bytes), nil
}

// readMetaData reads the metadata section from the input source.
func readMetaData(in io.Reader) (tlock.MetaData, error) {

	// ------------------------------------------------------------

	str, err := readBytes(in, maxUint64Len)
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

	roundNumber, err := strconv.ParseUint(string(roundStr), 10, 64)
	if err != nil {
		return tlock.MetaData{}, fmt.Errorf("convert round: %w", err)
	}

	// ------------------------------------------------------------

	str, err = readBytes(in, maxInt64Len)
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
	kyberPoint, err := readBytes(in, kyberPointLen)
	if err != nil {
		return tlock.CipherDEK{}, fmt.Errorf("read kyber point: %w", err)
	}

	cipherV, err := readBytes(in, cipherVLen)
	if err != nil {
		return tlock.CipherDEK{}, fmt.Errorf("read cipher v: %w", err)
	}

	cipherW, err := readBytes(in, cipherWLen)
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
	str, err := readBytes(in, maxInt64Len)
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
