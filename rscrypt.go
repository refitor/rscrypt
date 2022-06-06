package rscrypt

import (
	"crypto"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// aesKey: plain text
// publicKey: pem.memory
// privateKey: pem.memory
// signature: base64.EncodeToString

func Md5(data string) string {
	return string(sha256.Sum256([]byte(data))[:])
}

// =================== ECDH ====================================
// Generate elliptic curve key pair using secp256k1
func GenerateBitKey() ([]byte, []byte, error) {
	privateKey, err := ecies.GenerateKey(rand.Reader, secp256k1.S256(), nil)
	if err != nil {
		return nil, nil, err
	}

	privBuf, err := x509.MarshalECPrivateKey(privateKey.ExportECDSA())
	if err != nil {
		return nil, nil, err
	} else {
		privBuf = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBuf})
	}
	pubBuf, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	} else {
		pubBuf = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBuf})
	}
	return privBuf, pubBuf, nil
}

// Generate elliptic curve key pair using secp256r1
func GenerateEcdsaKey() ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privBuf, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	} else {
		privBuf = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBuf})
	}
	pubBuf, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	} else {
		pubBuf = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBuf})
	}
	return privBuf, pubBuf, nil
}

// https://asecuritysite.com/encryption/goecdh
func GetSharedKey(private, public []byte) ([]byte, error) {
	pubBlock, _ := pem.Decode(public)
	if pubBlock == nil {
		return nil, errors.New("public key error")
	}
	privBlock, _ := pem.Decode(private)
	if privBlock == nil {
		return nil, errors.New("private key error")
	}

	privSelf, err := x509.ParseECPrivateKey(privBlock.Bytes)
	if err != nil {
		return []byte{}, err
	}
	pubShared, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return []byte{}, err
	}
	pub := pubShared.(*ecdsa.PublicKey)
	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, privSelf.D.Bytes())
	retBuf := sha256.Sum256(x.Bytes())
	return retBuf[:], nil
}

func EcdsaSign(origData, privateKey []byte) (signature_encode string, err error) {
	privBlock, _ := pem.Decode(privateKey)
	if privBlock == nil {
		return "", errors.New("private key error")
	}
	private, err := x509.ParseECPrivateKey(privBlock.Bytes)
	if err != nil {
		return "", err
	}

	// sign
	hash := sha256.Sum256([]byte(origData))
	r, s, err := ecdsa.Sign(rand.Reader, private, hash[:])
	if err != nil {
		return "", err
	}

	// prepare a signature structure to marshal into json
	signature := &struct {
		R *big.Int
		S *big.Int
	}{
		R: r,
		S: s,
	}
	signature_json, err := json.Marshal(signature)
	if err != nil {
		return "", err
	}
	signature_encode = base64.StdEncoding.EncodeToString(signature_json)
	return signature_encode, nil
}

func EcdsaVerify(origData, signature string, publicKey []byte) error {
	pubBlock, _ := pem.Decode(publicKey)
	if pubBlock == nil {
		return errors.New("public key error")
	}
	public, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return err
	}

	sigBuf, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	tsig := &struct {
		R *big.Int
		S *big.Int
	}{}
	if err := json.Unmarshal(sigBuf, &tsig); err != nil {
		return err
	}
	hash := sha256.Sum256([]byte(origData))
	if !ecdsa.Verify(public.(*ecdsa.PublicKey), hash[:], tsig.R, tsig.S) {
		return errors.New("ecdsa verify failed")
	}
	return nil
}

func EcdsaEncrypt(origData, publicKey []byte) ([]byte, error) {
	pubBlock, _ := pem.Decode(publicKey)
	if pubBlock == nil {
		return nil, errors.New("public key error")
	}
	public, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, err
	}
	puk := ecies.ImportECDSAPublic(public.(*ecdsa.PublicKey))
	ct, err := ecies.Encrypt(rand.Reader, puk, origData, nil, nil)
	return ct, err
}

func EcdsaDecrypt(ciphertext, privateKey []byte) ([]byte, error) {
	privBlock, _ := pem.Decode(privateKey)
	if privBlock == nil {
		return nil, errors.New("private key error")
	}
	private, err := x509.ParseECPrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, err
	}
	prk := ecies.ImportECDSA(private)
	pt, err := prk.Decrypt(ciphertext, nil, nil)
	return pt, err
}

// =================== ECDH ====================================

// =================== RSA ====================================
// https://www.sohamkamani.com/golang/rsa-encryption/
func GenerateRsaKey() ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}
	privBuf := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	pubBuf := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)})
	return privBuf, pubBuf, nil
}

func RsaEncrypt(origData, publicKey []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}

func RsaDecrypt(ciphertext, privateKey []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}

func RsaSign(origData, privateKey []byte) (string, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return "", errors.New("public key error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(origData)
	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
	return base64.StdEncoding.EncodeToString(signature), nil
}

func RsaVerify(origData, signature, publicKey []byte) error {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return errors.New("public key error")
	}

	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return err
	}

	sig, err := base64.StdEncoding.DecodeString(string(signature))
	if err != nil {
		return err
	}
	hash := sha256.Sum256(origData)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sig)
}

// =================== RSA ======================

// =================== ECB ======================
func GenerateAesKey(data string) string {
	runesRandom := []rune(data)
	if len(runesRandom) < 32 {
		for i := 0; i < 32; i++ {
			data += "0"
		}
	}
	return data[:31]
}

func AesEncryptECB(origData []byte, key []byte) (encrypted []byte) {
	cipher, _ := aes.NewCipher(generateKey(key))
	length := (len(origData) + aes.BlockSize) / aes.BlockSize
	plain := make([]byte, length*aes.BlockSize)
	copy(plain, origData)
	pad := byte(len(plain) - len(origData))
	for i := len(origData); i < len(plain); i++ {
		plain[i] = pad
	}
	encrypted = make([]byte, len(plain))

	// block encryption
	for bs, be := 0, cipher.BlockSize(); bs <= len(origData); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Encrypt(encrypted[bs:be], plain[bs:be])
	}
	return encrypted
}

func AesDecryptECB(encrypted []byte, key []byte) (decrypted []byte) {
	cipher, _ := aes.NewCipher(generateKey(key))
	decrypted = make([]byte, len(encrypted))
	//
	for bs, be := 0, cipher.BlockSize(); bs < len(encrypted); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Decrypt(decrypted[bs:be], encrypted[bs:be])
	}

	trim := 0
	if len(decrypted) > 0 {
		trim = len(decrypted) - int(decrypted[len(decrypted)-1])
	}

	return decrypted[:trim]
}

func generateKey(key []byte) (genKey []byte) {
	genKey = make([]byte, 16)
	copy(genKey, key)
	for i := 16; i < len(key); {
		for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
			genKey[j] ^= key[i]
		}
	}
	return genKey
}

// =================== ECB ======================

// =================== random ===================
func GetRandomInt(max *big.Int) (int, error) {
	if max == nil {
		seed := "0123456789"
		alphanum := seed + fmt.Sprintf("%v", time.Now().UnixNano())
		max = big.NewInt(int64(len(alphanum)))
	}
	vrand, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, err
	}
	return int(vrand.Int64()), nil
}

func GetRandom(n int, isNO bool) string {
	seed := "0123456789"
	if !isNO {
		seed = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	}
	alphanum := seed + fmt.Sprintf("%v", time.Now().UnixNano())
	buffer := make([]byte, n)
	max := big.NewInt(int64(len(alphanum)))

	for i := 0; i < n; i++ {
		index, err := GetRandomInt(max)
		if err != nil {
			return ""
		}

		buffer[i] = alphanum[index]
	}
	return string(buffer)
}
