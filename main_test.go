package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestI2PDLeaseSetKeyIsRejected(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "leaseset.4.dat")
	data := make([]byte, 64)
	for i := range data {
		data[i] = byte(200 - i)
	}
	if err := os.WriteFile(keyPath, data, 0600); err != nil {
		t.Fatalf("write lease set key: %v", err)
	}

	_, err := loadKeyMaterial(keyPath)
	if err == nil {
		t.Fatal("expected i2pd .4.dat LeaseSet key to be rejected")
	}
	if !strings.Contains(err.Error(), "LeaseSet keys are not destination signing keys") {
		t.Fatalf("error = %q", err)
	}
}

func TestAddressbookSeedPubkeySignsWithStoredPublicKey(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	privateKey := ed25519.NewKeyFromSeed(seed)
	data := append([]byte(nil), seed...)
	data = append(data, privateKey[32:64]...)

	material := keyMaterial{
		format:      "Addressbook seed+pubkey",
		signSeed:    data[:32],
		signingPub:  ed25519.PublicKey(privateKey[32:64]),
		destination: privateKey[32:64],
	}

	message := "I owned generated.i2p"
	signatureB64 := signMessage(material.signSeed, message)
	signature, err := base64.StdEncoding.DecodeString(toStandardBase64(signatureB64))
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	if !ed25519.Verify(material.signingPub, []byte(message), signature) {
		t.Fatal("signature does not verify with generated public key")
	}
}

func TestFullI2PPrivateKeySignsWithPublicIdentity(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(255 - i)
	}

	privateKey := ed25519.NewKeyFromSeed(seed)
	signingPub := privateKey[32:64]

	identity := make([]byte, 391)
	copy(identity[352:384], signingPub)
	identity[384] = 5
	identity[386] = 4

	fullKey := append([]byte(nil), identity...)
	fullKey = append(fullKey, make([]byte, 256)...)
	fullKey = append(fullKey, seed...)

	keyPath := filepath.Join(t.TempDir(), "privatekey.dat")
	if err := os.WriteFile(keyPath, fullKey, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	material, err := loadKeyMaterial(keyPath)
	if err != nil {
		t.Fatalf("load key material: %v", err)
	}
	if material.format != "i2pd privatekey.dat (Identity + private keys)" {
		t.Fatalf("format = %q", material.format)
	}
	if len(material.destination) != len(identity) {
		t.Fatalf("destination length = %d, want %d", len(material.destination), len(identity))
	}

	message := "I owned full.i2p"
	signatureB64 := signMessage(material.signSeed, message)
	signature, err := base64.StdEncoding.DecodeString(toStandardBase64(signatureB64))
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(material.destination[352:384], []byte(message), signature) {
		t.Fatal("signature does not verify with signing public key from full identity")
	}
}
