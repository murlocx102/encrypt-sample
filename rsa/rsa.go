package decoder

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

// RSADecoder rsaDecoder.
type RSADecoder struct {
	KeyLength int
}

// NewRSADecoder Create an rsa decoding service
// key length,for safety, it is recommended not to be lower than 2048.
func NewRSADecoder(keyLength int) *RSADecoder {
	return &RSADecoder{
		KeyLength: keyLength,
	}
}

// GenKeysToString Generate rsa key pair and return string format.
// key format PKCS＃8.
func (r RSADecoder) GenKeysToString() (privStr, pubStr string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, r.KeyLength)
	if err != nil {
		return "", "", err
	}

	x509PrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}

	// private key to string
	priv := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509PrivateKey,
	}))

	// The public key is stored in the private key
	publicKey := privateKey.PublicKey

	x509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return "", "", err
	}

	pub := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509PublicKey,
	}))

	return priv, pub, nil
}

// SignByPriv rsa private key signature.
// Use rsa private key string for data signature,return base64 processing result.
func (r RSADecoder) SignByPriv(privateKey, data string) (result string, err error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return "", errors.New("private key error！")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

    // Signature data is hashed
	hash := sha256.Sum256([]byte(data))
	// RSA digital signature
	sign, err := rsa.SignPKCS1v15(rand.Reader, priv.(*rsa.PrivateKey), crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}

	// base64 processing result
	return base64.StdEncoding.EncodeToString(sign), nil
}

// VerifyByPub rsa public key verification.
// Original signature data is required for verification.
func (r RSADecoder) VerifyByPub(publicKey, sign, data string) (result bool, err error) {
	block, _ := pem.Decode([]byte(publicKey))
    if block == nil {
		return false, errors.New("public key error！")
	}
	
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
		return false, err
	}
    
	hash := sha256.Sum256([]byte(data))

	// signature base64 decode 
	bytes, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, hash[:], bytes)
	if err != nil {
		return false, err
	}

	return true, nil
}
