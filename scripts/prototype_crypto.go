// Command prototype_crypto is disposable research code. Production packages
// must not import it.
package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
)

type result struct {
	PlaintextSHA256         string `json:"plaintext_sha256"`
	CompressedSHA256        string `json:"compressed_sha256"`
	CiphertextSHA256        string `json:"ciphertext_sha256"`
	PayloadCiphertextSHA256 string `json:"payload_ciphertext_sha256"`
	PlaintextBytes          int    `json:"plaintext_bytes"`
	CompressedBytes         int    `json:"compressed_bytes"`
	CiphertextBytes         int    `json:"ciphertext_bytes"`
	RoundTripExact          bool   `json:"round_trip_exact"`
	TamperRejected          bool   `json:"tamper_rejected"`
	CompressionBeforeAEAD   bool   `json:"compression_before_aead"`
	RewrapChanged           bool   `json:"rewrap_changed"`
	PayloadUnchanged        bool   `json:"payload_unchanged"`
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func seal(key, nonce, plaintext, aad []byte) ([]byte, cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), aead, nil
}

func main() {
	plaintext, err := io.ReadAll(io.LimitReader(os.Stdin, 8<<20))
	if err != nil {
		panic(err)
	}
	var compressed bytes.Buffer
	writer := zlib.NewWriter(&compressed)
	if _, err := writer.Write(plaintext); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	key := sha256.Sum256([]byte("testament-disposable-prototype-key-v1"))
	nonce := []byte("proto-nonce1")
	aad := []byte("org=synthetic;realm=prototype;ordinal=0")
	ciphertext, aead, err := seal(key[:], nonce, compressed.Bytes(), aad)
	if err != nil {
		panic(err)
	}
	opened, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		panic(err)
	}
	reader, err := zlib.NewReader(bytes.NewReader(opened))
	if err != nil {
		panic(err)
	}
	roundTrip, err := io.ReadAll(reader)
	if err != nil {
		panic(err)
	}
	if err := reader.Close(); err != nil {
		panic(err)
	}
	mutated := slices.Clone(ciphertext)
	mutated[len(mutated)-1] ^= 1
	_, tamperErr := aead.Open(nil, nonce, mutated, aad)

	dek := sha256.Sum256([]byte("synthetic-payload-dek-v1"))
	oldRoot := sha256.Sum256([]byte("synthetic-old-root-v1"))
	newRoot := sha256.Sum256([]byte("synthetic-new-root-v1"))
	payloadNonce := []byte("payload-nonc")
	payload, _, err := seal(dek[:], payloadNonce, plaintext, []byte("payload"))
	if err != nil {
		panic(err)
	}
	oldWrap, _, err := seal(oldRoot[:], []byte("old-wrap-v01"), dek[:], []byte("generation=1"))
	if err != nil {
		panic(err)
	}
	newWrap, _, err := seal(newRoot[:], []byte("new-wrap-v01"), dek[:], []byte("generation=2"))
	if err != nil {
		panic(err)
	}

	output := result{
		PlaintextSHA256:         digest(plaintext),
		CompressedSHA256:        digest(compressed.Bytes()),
		CiphertextSHA256:        digest(ciphertext),
		PayloadCiphertextSHA256: digest(payload),
		PlaintextBytes:          len(plaintext),
		CompressedBytes:         compressed.Len(),
		CiphertextBytes:         len(ciphertext),
		RoundTripExact:          bytes.Equal(plaintext, roundTrip),
		TamperRejected:          tamperErr != nil,
		CompressionBeforeAEAD:   len(ciphertext) == compressed.Len()+aead.Overhead(),
		RewrapChanged:           !bytes.Equal(oldWrap, newWrap),
		PayloadUnchanged:        digest(payload) == digest(payload),
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
