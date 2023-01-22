package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"reflect"
)

// EllipticCurve struct
type EllipticCurve struct {
	pubKeyCurve elliptic.Curve // http://golang.org/pkg/crypto/elliptic/#P256
	privateKey  *ecdsa.PrivateKey
	publicKey   *ecdsa.PublicKey
}

// New EllipticCurve
func New(curve elliptic.Curve) *EllipticCurve {
	return &EllipticCurve{
		pubKeyCurve: curve,
		privateKey:  new(ecdsa.PrivateKey),
	}
}

// GenerateKeys EllipticCurve public and private keys
func (ec *EllipticCurve) GenerateKeys() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {

	var err error
	privKey, err := ecdsa.GenerateKey(ec.pubKeyCurve, rand.Reader)

	if err == nil {
		ec.privateKey = privKey
		ec.publicKey = &privKey.PublicKey
	}

	return ec.privateKey, ec.publicKey, err
}

type some struct {
}

// EncodePrivate private key
func (ec *EllipticCurve) EncodePrivate(privKey *ecdsa.PrivateKey) (string, error) {

	encoded, err := x509.MarshalECPrivateKey(privKey)

	if err != nil {
		return "", err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})

	return string(pemEncoded), nil
}

// EncodePublic public key
func (ec *EllipticCurve) EncodePublic(pubKey *ecdsa.PublicKey) (string, error) {

	encoded, err := x509.MarshalPKIXPublicKey(pubKey)

	if err != nil {
		return "", err
	}
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})

	return string(pemEncodedPub), nil
}

// DecodePrivate private key
func (ec *EllipticCurve) DecodePrivate(pemEncodedPriv string) (*ecdsa.PrivateKey, error) {
	blockPriv, _ := pem.Decode([]byte(pemEncodedPriv))

	x509EncodedPriv := blockPriv.Bytes

	privateKey, err := x509.ParseECPrivateKey(x509EncodedPriv)

	return privateKey, err
}

// DecodePublic public key
func (ec *EllipticCurve) DecodePublic(pemEncodedPub string) (*ecdsa.PublicKey, error) {
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))

	x509EncodedPub := blockPub.Bytes

	genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	return publicKey, err
}

// VerifySignature sign ecdsa style and verify signature
func (ec *EllipticCurve) VerifySignature(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) ([]byte, bool, error) {

	var h hash.Hash
	h = md5.New()
	r := big.NewInt(0)
	s := big.NewInt(0)

	io.WriteString(h, "This is a message to be signed and verified by ECDSA!")
	signhash := h.Sum(nil)

	r, s, serr := ecdsa.Sign(rand.Reader, privKey, signhash)
	if serr != nil {
		return []byte(""), false, serr
	}

	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)

	verify := ecdsa.Verify(pubKey, signhash, r, s)

	return signature, verify, nil
}

// Test encode, decode and test it with deep equal
func (ec *EllipticCurve) Test(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) error {

	encPriv, err := ec.EncodePrivate(privKey)
	if err != nil {
		return err
	}
	encPub, err := ec.EncodePublic(pubKey)
	if err != nil {
		return err
	}
	priv2, err := ec.DecodePrivate(encPriv)
	if err != nil {
		return err
	}
	pub2, err := ec.DecodePublic(encPub)
	if err != nil {
		return err
	}

	if !reflect.DeepEqual(privKey, priv2) {
		return errors.New("private keys do not match")
	}
	if !reflect.DeepEqual(pubKey, pub2) {
		return errors.New("public keys do not match")
	}

	return nil
}

func test_verify(pubkey, message, signed_msg string) bool {
	x := New(elliptic.P224())
	pub, _err := x.DecodePublic(pubkey)
	fmt.Print("Nile\n", _err)
	hash := sha256.Sum256([]byte(message))
	sDec, _ := b64.StdEncoding.DecodeString(signed_msg)
	valid := ecdsa.VerifyASN1(pub, hash[:], sDec)
	return valid

}
func test_sign(privkey, message string) string {
	x := New(elliptic.P224())
	priv, _err := x.DecodePrivate(privkey)
	hash := sha256.Sum256([]byte(message))
	sig, _err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	fmt.Print("Nile\n", _err)
	sEnc := b64.StdEncoding.EncodeToString([]byte(sig))
	return sEnc
}

func main() {
	pubkey := "-----BEGIN PUBLIC KEY-----\nME4wEAYHKoZIzj0CAQYFK4EEACEDOgAE5puDej67SK0akoj0E3ocGplYObQcx/ii\nQQ5yMe6l3ogZWNm3bCbvEZ+kCUBJoeSi3SV7IFFiX4E=\n-----END PUBLIC KEY-----"
	privkey := "-----BEGIN PRIVATE KEY-----\nMGgCAQEEHFZohAYiPIo97TdVQTGKPyghByr+3bfhX2ryOmqgBwYFK4EEACGhPAM6\nAATmm4N6PrtIrRqSiPQTehwamVg5tBzH+KJBDnIx7qXeiBlY2bdsJu8Rn6QJQEmh\n5KLdJXsgUWJfgQ==\n-----END PRIVATE KEY-----"
	msg := "Hello, world"

	// Generated in Python
	signed_message_base64 := "MD0CHQD/GfTl6loV0rBNun+85eM0HfhmK5aAgRKNQyeUAhxVhbg3CKKYx1pKLTHAr8Kkozd+7S25X5FomxHC"

	fmt.Println("\n Verfied: ", test_verify(pubkey, msg, signed_message_base64))
	fmt.Println("\n Signed Base64: ", test_sign(privkey, msg))
}
