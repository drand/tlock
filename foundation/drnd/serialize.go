package drnd

import (
	"bufio"
	"fmt"
	"io"
	"strconv"

	"github.com/drand/kyber/encrypt/ibe"
)

// write the meta data and encrypted data to the destination.
func write(dst io.Writer, cipherDek *ibe.Ciphertext, cipherText []byte, roundID uint64, chainHash string) error {
	kyberPoint, err := cipherDek.U.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal binary: %w", err)
	}

	fmt.Fprintln(dst, strconv.Itoa(int(roundID)))
	fmt.Fprintln(dst, chainHash)

	ww := bufio.NewWriter(dst)
	defer ww.Flush()

	fmt.Fprintf(ww, "%010d", len(kyberPoint))
	ww.Write(kyberPoint)

	fmt.Fprintf(ww, "%010d", len(cipherDek.V))
	ww.Write(cipherDek.V)

	fmt.Fprintf(ww, "%010d", len(cipherDek.W))
	ww.Write(cipherDek.W)

	fmt.Fprintf(ww, "%010d", len(cipherText))
	ww.Write(cipherText)

	return nil
}

// cipherDex represents the different parts of the Data Encryption Key.
type dek struct {
	kyberPoint []byte
	cipherV    []byte
	cipherW    []byte
}

// cipherInfo represents the different parts of the encrypted source.
type cipherInfo struct {
	roundID   uint64
	chainHash string
	dek       dek
	text      []byte
}

// read the encrypted data into its different parts.
func read(src io.Reader) (cipherInfo, error) {
	rr := bufio.NewReader(src)

	roundIDStr, err := readHeaderLine(rr)
	if err != nil {
		return cipherInfo{}, fmt.Errorf("failed to read roundID: %w", err)
	}

	roundID, err := strconv.Atoi(roundIDStr)
	if err != nil {
		return cipherInfo{}, fmt.Errorf("failed to convert round: %w", err)
	}

	chainHash, err := readHeaderLine(rr)
	if err != nil {
		return cipherInfo{}, fmt.Errorf("failed to read chain hash: %w", err)
	}

	kyberPoint, err := readPayloadBytes(rr)
	if err != nil {
		return cipherInfo{}, fmt.Errorf("failed to read kyber point: %w", err)
	}

	cipherV, err := readPayloadBytes(rr)
	if err != nil {
		return cipherInfo{}, fmt.Errorf("failed to read cipher v: %w", err)
	}

	cipherW, err := readPayloadBytes(rr)
	if err != nil {
		return cipherInfo{}, fmt.Errorf("failed to read cipher w: %w", err)
	}

	cipherText, err := readPayloadBytes(rr)
	if err != nil {
		return cipherInfo{}, fmt.Errorf("failed to read cipher text w: %w", err)
	}

	ci := cipherInfo{
		roundID:   uint64(roundID),
		chainHash: chainHash,
		dek: dek{
			kyberPoint: kyberPoint,
			cipherV:    cipherV,
			cipherW:    cipherW,
		},
		text: cipherText,
	}

	return ci, nil
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
