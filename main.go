package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

type keyMaterial struct {
	format       string
	signSeed     []byte
	signingPub   ed25519.PublicKey
	destination  []byte
	destinationB string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./i2p-signer <command> [args]")
		fmt.Println("")
		fmt.Println("Commands:")
		fmt.Println("  sign <keys.dat> <message>    Sign a message with Ed25519 private key")
		fmt.Println("  gen-key [outputfile]         Generate a new 64-byte key file (seed + pubkey)")
		fmt.Println("  inspect <keys.dat>           Extract and display key information")
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Println("  ./i2p-signer sign my-keys.dat \"I owned domain.i2p\"")
		fmt.Println("  ./i2p-signer gen-key my-new-key.dat")
		fmt.Println("  ./i2p-signer inspect my-key.dat")
		return
	}

	command := os.Args[1]

	switch command {
	case "gen-key":
		genKey(os.Args[2:])
	case "sign":
		if len(os.Args) < 4 {
			fmt.Println("Usage: ./i2p-signer sign <path_to_keys.dat> <message>")
			os.Exit(1)
		}
		sign(os.Args[2], os.Args[3])
	case "inspect":
		if len(os.Args) < 3 {
			fmt.Println("Usage: ./i2p-signer inspect <path_to_keys.dat>")
			os.Exit(1)
		}
		inspect(os.Args[2])
	default:
		fmt.Printf("Unknown command: %s\n", command)
		fmt.Println("Run ./i2p-signer without args to see usage")
		os.Exit(1)
	}
}

func genKey(args []string) {
	var outputPath string
	if len(args) > 0 && args[0] != "" {
		outputPath = args[0]
	} else {
		// Default filename
		outputPath = "i2p-key.dat"
	}

	// Generate a random 32-byte seed
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		fmt.Printf("Error generating random seed: %v\n", err)
		os.Exit(1)
	}

	// Generate private key from seed
	privateKey := ed25519.NewKeyFromSeed(seed)

	// The 64-byte format: seed (32 bytes) + public key (32 bytes)
	output := make([]byte, 64)
	copy(output[:32], seed)
	copy(output[32:], privateKey[32:64])

	// Write to file
	if err := os.WriteFile(outputPath, output, 0600); err != nil {
		fmt.Printf("Error writing key file: %v\n", err)
		os.Exit(1)
	}

	// Show the public key (destination) in both formats
	pubKey := privateKey[32:64]
	stdBase64 := base64.StdEncoding.EncodeToString(pubKey)
	i2pBase64 := toI2PBase64(stdBase64)

	fmt.Printf("Key generated: %s\n", outputPath)
	fmt.Printf("I2P Destination (for registration): %s\n", i2pBase64)
	fmt.Printf("Public key (Base64): %s\n", stdBase64)
	fmt.Println("")
	fmt.Println("=== TO REGISTER THIS DOMAIN ===")
	fmt.Println("You must sign a challenge to prove ownership of your key.")
	fmt.Println("")
	fmt.Println("To register a domain, run:")
	fmt.Printf("  ./i2p-signer sign %s \"Register <your-domain.i2p> at YYYY-MM-DD\"\n", outputPath)
	fmt.Println("")
	fmt.Println("Example:")
	fmt.Printf("  ./i2p-signer sign %s \"Register mysite.i2p at 2026-04-20\"\n", outputPath)
}

// toI2PBase64 converts standard Base64 to I2P alphabet
func toI2PBase64(stdB64 string) string {
	replacer := strings.NewReplacer("+", "-", "/", "~")
	return replacer.Replace(stdB64)
}

// toStandardBase64 converts I2P alphabet to standard Base64
func toStandardBase64(i2pB64 string) string {
	replacer := strings.NewReplacer("-", "+", "~", "/")
	return replacer.Replace(i2pB64)
}

func loadKeyMaterial(keyPath string) (*keyMaterial, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	if len(data) < 64 {
		return nil, fmt.Errorf("key file too short: expected at least 64 bytes, got %d", len(data))
	}

	if len(data) == 64 {
		seed := data[:32]
		privateKey := ed25519.NewKeyFromSeed(seed)
		derivedPub := privateKey[32:64]

		if equalBytes(derivedPub, data[32:64]) {
			destination := append([]byte(nil), derivedPub...)
			return &keyMaterial{
				format:       "i2p-signer seed+pubkey",
				signSeed:     append([]byte(nil), seed...),
				signingPub:   append(ed25519.PublicKey(nil), derivedPub...),
				destination:  destination,
				destinationB: toI2PBase64(base64.StdEncoding.EncodeToString(destination)),
			}, nil
		}

		return nil, fmt.Errorf("unsupported 64-byte key format: expected i2p-signer seed+pubkey; i2pd .4.dat/.6.dat LeaseSet keys are not destination signing keys")
	}

	if material, ok, err := loadFullI2PPrivateKey(data); ok || err != nil {
		return material, err
	}

	if len(data) >= 68 {
		seed := data[4:36]
		expectedPub := data[36:68]
		privateKey := ed25519.NewKeyFromSeed(seed)
		derivedPub := privateKey[32:64]
		if equalBytes(derivedPub, expectedPub) {
			destination := append([]byte(nil), derivedPub...)
			return &keyMaterial{
				format:       "Header + Ed25519 seed+pubkey",
				signSeed:     append([]byte(nil), seed...),
				signingPub:   append(ed25519.PublicKey(nil), derivedPub...),
				destination:  destination,
				destinationB: toI2PBase64(base64.StdEncoding.EncodeToString(destination)),
			}, nil
		}
	}

	return nil, fmt.Errorf("unsupported key format: %d bytes", len(data))
}

func loadFullI2PPrivateKey(data []byte) (*keyMaterial, bool, error) {
	publicLen, ok := i2pIdentityLength(data)
	if !ok {
		return nil, false, nil
	}
	if len(data) < publicLen+32 {
		return nil, true, fmt.Errorf("full I2P key is too short: %d bytes", len(data))
	}

	signSeed := data[len(data)-32:]
	privateKey := ed25519.NewKeyFromSeed(signSeed)
	signingPub := privateKey[32:64]
	expectedPub := data[352:384]
	if !equalBytes(signingPub, expectedPub) {
		return nil, true, fmt.Errorf("unsupported full I2P key: Ed25519 signing seed does not match public identity")
	}

	destination := append([]byte(nil), data[:publicLen]...)
	return &keyMaterial{
		format:       "i2pd privatekey.dat (Identity + private keys)",
		signSeed:     append([]byte(nil), signSeed...),
		signingPub:   append(ed25519.PublicKey(nil), signingPub...),
		destination:  destination,
		destinationB: toI2PBase64(base64.StdEncoding.EncodeToString(destination)),
	}, true, nil
}

func i2pIdentityLength(data []byte) (int, bool) {
	const defaultIdentityLen = 387
	if len(data) < defaultIdentityLen {
		return 0, false
	}

	extendedLen := int(data[385])<<8 | int(data[386])
	publicLen := defaultIdentityLen + extendedLen
	if publicLen > len(data) {
		return 0, false
	}
	return publicLen, true
}

func signMessage(seed []byte, message string) string {
	privateKey := ed25519.NewKeyFromSeed(seed)
	signature := ed25519.Sign(privateKey, []byte(message))
	return toI2PBase64(base64.StdEncoding.EncodeToString(signature))
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// inspect extracts and displays key information from a key file
func inspect(keyPath string) {
	material, err := loadKeyMaterial(keyPath)
	if err != nil {
		fmt.Printf("Error reading key file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("File: %s\n", keyPath)
	fmt.Printf("Detected format: %s\n", material.format)

	// Output Public Key (Hex)
	fmt.Printf("\n=== Signing Public Key (Hex) ===\n")
	fmt.Printf("%s\n", hex.EncodeToString(material.signingPub))

	// Output Full Destination (Base64 I2P format)
	fmt.Printf("\n=== Destination (I2P Base64) ===\n")
	fmt.Printf("%s\n", material.destinationB)

	// Output Base32 Address
	b32Addr := computeBase32(material.destination)
	fmt.Printf("\n=== Base32 Address (.b32.i2p) ===\n")
	fmt.Printf("%s\n", b32Addr)

	// Summary for verification
	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Use this destination for registration: %s\n", material.destinationB)
	fmt.Printf("Verify with i2pd console at: http://[%s]:7070/\n", b32Addr)
}

// computeBase32 computes the .b32.i2p address from destination bytes.
func computeBase32(destination []byte) string {
	hash := sha256.Sum256(destination)
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:])
	return strings.ToLower(b32) + ".b32.i2p"
}

func sign(keyPath, message string) {
	material, err := loadKeyMaterial(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading key file: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(signMessage(material.signSeed, message))
}
