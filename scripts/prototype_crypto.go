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
	"path/filepath"
	"slices"
)

type capture struct {
	CaptureID   string `json:"capture_id"`
	Method      string `json:"method"`
	Phase       string `json:"phase"`
	ReadOrdinal int    `json:"read_ordinal"`
	ByteCount   int    `json:"byte_count"`
	SHA256      string `json:"sha256"`
}

type wrappedDEK struct {
	PersistedPath string `json:"persisted_path"`
	Generation    int    `json:"generation"`
	ByteCount     int    `json:"byte_count"`
	SHA256        string `json:"sha256"`
}

type result struct {
	PlaintextSHA256          string     `json:"plaintext_sha256"`
	CompressedSHA256         string     `json:"compressed_sha256"`
	CiphertextSHA256         string     `json:"ciphertext_sha256"`
	PayloadCiphertextSHA256  string     `json:"payload_ciphertext_sha256"`
	PreRewrapPayloadCapture  capture    `json:"pre_rewrap_payload_capture"`
	PostRewrapPayloadCapture capture    `json:"post_rewrap_payload_capture"`
	OldWrappedDEK            wrappedDEK `json:"old_wrapped_dek"`
	NewWrappedDEK            wrappedDEK `json:"new_wrapped_dek"`
	OperationSequence        []string   `json:"operation_sequence"`
	Generations              []int      `json:"generations"`
	ResumeCheckpoint         int        `json:"resume_checkpoint"`
	PlaintextBytes           int        `json:"plaintext_bytes"`
	CompressedBytes          int        `json:"compressed_bytes"`
	CiphertextBytes          int        `json:"ciphertext_bytes"`
	RoundTripExact           bool       `json:"round_trip_exact"`
	TamperRejected           bool       `json:"tamper_rejected"`
	CompressionBeforeAEAD    bool       `json:"compression_before_aead"`
	RewrapChanged            bool       `json:"rewrap_changed"`
	PayloadUnchanged         bool       `json:"payload_unchanged"`
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
	store, err := os.MkdirTemp("", "testament-key-rotation-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(store)
	payloadPath := filepath.Join(store, "payload_ciphertext.bin")
	oldWrapPath := filepath.Join(store, "wrapped_dek.generation-1.bin")
	newWrapPath := filepath.Join(store, "wrapped_dek.generation-2.bin")
	checkpointPath := filepath.Join(store, "rewrap.checkpoint")
	if err := os.WriteFile(payloadPath, payload, 0o600); err != nil {
		panic(err)
	}
	if err := os.WriteFile(oldWrapPath, oldWrap, 0o600); err != nil {
		panic(err)
	}
	preRewrapPayload, err := os.ReadFile(payloadPath)
	if err != nil {
		panic(err)
	}
	newWrap, _, err := seal(newRoot[:], []byte("new-wrap-v01"), dek[:], []byte("generation=2"))
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(newWrapPath, newWrap, 0o600); err != nil {
		panic(err)
	}
	if err := os.WriteFile(checkpointPath, []byte("1\n"), 0o600); err != nil {
		panic(err)
	}
	if os.Getenv("TESTAMENT_KEY_ROTATION_MUTATION") == "payload-byte" {
		changedPayload := slices.Clone(payload)
		changedPayload[len(changedPayload)-1] ^= 1
		if err := os.WriteFile(payloadPath, changedPayload, 0o600); err != nil {
			panic(err)
		}
	}
	postRewrapPayload, err := os.ReadFile(payloadPath)
	if err != nil {
		panic(err)
	}
	preDigest := digest(preRewrapPayload)
	postDigest := digest(postRewrapPayload)
	oldWrapDigest := digest(oldWrap)
	newWrapDigest := digest(newWrap)
	payloadUnchanged := preDigest == postDigest &&
		len(preRewrapPayload) == len(postRewrapPayload)
	rewrapChanged := oldWrapDigest != newWrapDigest

	output := result{
		PlaintextSHA256:         digest(plaintext),
		CompressedSHA256:        digest(compressed.Bytes()),
		CiphertextSHA256:        digest(ciphertext),
		PayloadCiphertextSHA256: preDigest,
		PreRewrapPayloadCapture: capture{
			CaptureID:   "payload_ciphertext.bin:read-1-before-rewrap",
			Method:      "os.ReadFile persisted payload_ciphertext.bin",
			Phase:       "immediately-before-rewrap",
			ReadOrdinal: 1,
			ByteCount:   len(preRewrapPayload),
			SHA256:      preDigest,
		},
		PostRewrapPayloadCapture: capture{
			CaptureID:   "payload_ciphertext.bin:read-2-after-checkpoint",
			Method:      "os.ReadFile persisted payload_ciphertext.bin",
			Phase:       "after-new-wrapped-dek-and-checkpoint",
			ReadOrdinal: 2,
			ByteCount:   len(postRewrapPayload),
			SHA256:      postDigest,
		},
		OldWrappedDEK: wrappedDEK{
			PersistedPath: "wrapped_dek.generation-1.bin",
			Generation:    1,
			ByteCount:     len(oldWrap),
			SHA256:        oldWrapDigest,
		},
		NewWrappedDEK: wrappedDEK{
			PersistedPath: "wrapped_dek.generation-2.bin",
			Generation:    2,
			ByteCount:     len(newWrap),
			SHA256:        newWrapDigest,
		},
		OperationSequence: []string{
			"pre_payload_capture",
			"new_wrapped_dek_persisted",
			"checkpoint_persisted",
			"post_payload_capture",
		},
		Generations:           []int{1, 2},
		ResumeCheckpoint:      1,
		PlaintextBytes:        len(plaintext),
		CompressedBytes:       compressed.Len(),
		CiphertextBytes:       len(ciphertext),
		RoundTripExact:        bytes.Equal(plaintext, roundTrip),
		TamperRejected:        tamperErr != nil,
		CompressionBeforeAEAD: len(ciphertext) == compressed.Len()+aead.Overhead(),
		RewrapChanged:         rewrapChanged,
		PayloadUnchanged:      payloadUnchanged,
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
