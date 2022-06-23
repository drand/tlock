package drnd

import (
	"bufio"
	"bytes"
	"encoding/pem"
	"fmt"
	"io"
	"strconv"

	"github.com/drand/kyber/encrypt/ibe"
)

// metadata represents the metadata maintained in the encrypted output.
type metadata struct {
	roundID   uint64
	chainHash string
}

// cipherDex represents the different parts of the Data Encryption Key.
type dek struct {
	kyberPoint []byte
	cipherV    []byte
	cipherW    []byte
}

// fileInfo represents the different parts of the encrypted source.
type fileInfo struct {
	metadata   metadata
	dek        dek
	cipherText []byte
}

// =============================================================================

// write the meta data, cipher DEK and cipher text to the output destination.
func write(out io.Writer, cipherDEK *ibe.Ciphertext, cipherText []byte, md metadata, armor bool) (err error) {
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

	fmt.Fprintln(ww, strconv.Itoa(int(md.roundID)))
	fmt.Fprintln(ww, md.chainHash)

	fmt.Fprintf(ww, "%010d", len(kyberPoint))
	ww.Write(kyberPoint)

	fmt.Fprintf(ww, "%010d", len(cipherDEK.V))
	ww.Write(cipherDEK.V)

	fmt.Fprintf(ww, "%010d", len(cipherDEK.W))
	ww.Write(cipherDEK.W)

	fmt.Fprintf(ww, "%010d", len(cipherText))
	ww.Write(cipherText)

	return nil
}

// read the encrypted data into its different parts.
func read(in io.Reader) (fileInfo, error) {
	data, err := io.ReadAll(in)
	if err != nil {
		return fileInfo{}, fmt.Errorf("failed to read the data from source: %w", err)
	}

	rr := bufio.NewReader(bytes.NewReader(data))
	if string(data[:5]) == "-----" {
		var block *pem.Block
		if block, _ = pem.Decode(data); block == nil {
			return fileInfo{}, fmt.Errorf("decoding PEM: %s", "block is nil")
		}

		rr = bufio.NewReader(bytes.NewReader(block.Bytes))
	}

	roundIDStr, err := readHeaderLine(rr)
	if err != nil {
		return fileInfo{}, fmt.Errorf("failed to read roundID: %w", err)
	}

	roundID, err := strconv.Atoi(roundIDStr)
	if err != nil {
		return fileInfo{}, fmt.Errorf("failed to convert round: %w", err)
	}

	chainHash, err := readHeaderLine(rr)
	if err != nil {
		return fileInfo{}, fmt.Errorf("failed to read chain hash: %w", err)
	}

	kyberPoint, err := readPayloadBytes(rr)
	if err != nil {
		return fileInfo{}, fmt.Errorf("failed to read kyber point: %w", err)
	}

	cipherV, err := readPayloadBytes(rr)
	if err != nil {
		return fileInfo{}, fmt.Errorf("failed to read cipher v: %w", err)
	}

	cipherW, err := readPayloadBytes(rr)
	if err != nil {
		return fileInfo{}, fmt.Errorf("failed to read cipher w: %w", err)
	}

	cipherText, err := readPayloadBytes(rr)
	if err != nil {
		return fileInfo{}, fmt.Errorf("failed to read cipher text w: %w", err)
	}

	fi := fileInfo{
		metadata: metadata{
			roundID:   uint64(roundID),
			chainHash: chainHash,
		},
		dek: dek{
			kyberPoint: kyberPoint,
			cipherV:    cipherV,
			cipherW:    cipherW,
		},
		cipherText: cipherText,
	}

	return fi, nil
}

// readPayloadBytes reads the section of the payload.
func readPayloadBytes(rr *bufio.Reader) ([]byte, error) {
	lenStr := make([]byte, 10)
	if _, err := rr.Read(lenStr); err != nil {
		return nil, err
	}

	len, err := strconv.Atoi(string(lenStr))
	if err != nil {
		return nil, err
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
