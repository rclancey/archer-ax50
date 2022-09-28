package ax50

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	crand "crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"strconv"
	"time"
)

func Pad(data []byte, size int) []byte {
	n := size - (len(data) % size)
	padded := make([]byte, len(data) + n)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(n)
	}
	return padded
}

func Unpad(data []byte) []byte {
	n := len(data)
	padding := int(data[n-1])
	return data[:n-padding]
}

type AESCipher struct {
	block cipher.Block
	key []byte
	iv []byte
}

func NewAESCipher(key, iv string) (*AESCipher, error) {
	if len(key) < aes.BlockSize || len(iv) < aes.BlockSize {
		return nil, fmt.Errorf("key or iv is too short")
	}
	keyBytes := []byte(key)[:aes.BlockSize]
	ivBytes  := []byte(iv)[:aes.BlockSize]
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}
	return &AESCipher{block, keyBytes, ivBytes}, nil
}

func GenAESCipher() (*AESCipher, error) {
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	k1 := strconv.FormatInt(rand.Int63n(1000000000) + 100000000, 10)
	k2 := strconv.FormatInt(rand.Int63n(1000000000) + 100000000, 10)
	return NewAESCipher(ts+k1, ts+k2)
}

func (c *AESCipher) Key() string {
	return string(c.key)
}

func (c *AESCipher) IV() string {
	return string(c.iv)
}

func (c *AESCipher) Encrypt(data []byte) ([]byte, error) {
	enc := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(c.block, c.iv)
	mode.CryptBlocks(enc, data)
	return enc, nil
}

func (c *AESCipher) EncryptHex(data []byte) (string, error) {
	enc, err := c.Encrypt(data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(enc), nil
}

func (c *AESCipher) EncryptBase64(data []byte) (string, error) {
	enc, err := c.Encrypt(data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(enc), nil
}

func (c *AESCipher) Decrypt(data []byte) ([]byte, error) {
	dec := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(c.block, c.iv)
	mode.CryptBlocks(dec, data)
	return dec, nil
}

func (c *AESCipher) DecryptHex(data string) ([]byte, error) {
	enc, err := hex.DecodeString(data)
	if err != nil {
		return nil, err
	}
	return c.Decrypt(enc)
}

func (c *AESCipher) DecryptBase64(data string) ([]byte, error) {
	enc, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	return c.Decrypt(enc)
}

type RSACipher struct {
	key *rsa.PublicKey
}

func (c *RSACipher) Encrypt(data []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(crand.Reader, c.key, data)
}

func (c *RSACipher) EncryptHex(data []byte) (string, error) {
	enc, err := c.Encrypt(data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(enc), nil
}

func (c *RSACipher) EncryptBase64(data []byte) (string, error) {
	enc, err := c.Encrypt(data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(enc), nil
}

type RSASigner struct {
	hashedPw string
	key *RSACipher
	seq int
	aes *AESCipher
}

func ParseRSAKey(key []string) (*RSACipher, error) {
	if len(key) != 2 {
		return nil, fmt.Errorf("expecting 2 strings")
	}
	keyBytes, err := hex.DecodeString(key[0])
	if err != nil {
		return nil, err
	}
	n := big.NewInt(0).SetBytes(keyBytes)
	e, err := strconv.ParseInt(key[1], 16, 64)
	if err != nil {
		return nil, err
	}
	pubKey := &rsa.PublicKey{N: n, E: int(e)}
	return &RSACipher{pubKey}, nil
}

func NewRSASigner(password string, key []string, seq int, aesKey *AESCipher) (*RSASigner, error) {
	sum := md5.Sum([]byte("admin"+password))
	hashedPw := hex.EncodeToString(sum[:])
	pubKey, err := ParseRSAKey(key)
	if err != nil {
		return nil, err
	}
	return &RSASigner{
		hashedPw: hashedPw,
		key: pubKey,
		seq: seq,
		aes: aesKey,
	}, nil
}

func (signer *RSASigner) getData(dataLen int, isLogin bool) string {
	if isLogin && signer.aes != nil {
		return fmt.Sprintf("k=%s&i=%s&h=%s&s=%d", signer.aes.Key(), signer.aes.IV(), signer.hashedPw, signer.seq + dataLen)
	}
	return fmt.Sprintf("h=%s&s=%d", signer.hashedPw, signer.seq + dataLen)
}

func (signer *RSASigner) genSignature(dataLen int, isLogin bool) (string, error) {
	signData := []byte(signer.getData(dataLen, isLogin))
	signature := ""
	pos := 0
	maxN := len(signData)
	for pos < maxN {
		n := pos + 53
		if n > maxN {
			n = maxN
		}
		cipherText, err := signer.key.EncryptHex(signData[pos:n])
		if err != nil {
			return "", err
		}
		signature += cipherText
		pos += 53
	}
	return signature, nil
}

type EncryptedFormData struct {
	Sign string `json:"sign"`
	Data string `json:"data"`
}

func (signer *RSASigner) Sign(data interface{}, isLogin bool) (*EncryptedFormData, error) {
	dataStr, err := MarshalForm(data)
	if err != nil {
		return nil, err
	}
	plainBytes := Pad(dataStr, aes.BlockSize)
	cipherText, err := signer.aes.EncryptBase64(plainBytes)
	if err != nil {
		return nil, err
	}
	sig, err := signer.genSignature(len(cipherText), isLogin)
	if err != nil {
		return nil, err
	}
	return &EncryptedFormData{Sign: sig, Data: cipherText}, nil
}

type EncryptedResponse struct {
	Data string `json:"data"`
}

func (signer *RSASigner) DecryptResponse(body []byte) ([]byte, error) {
	encResp := &EncryptedResponse{}
	err := json.Unmarshal(body, encResp)
	if err != nil {
		return nil, err
	}
	plainText, err := signer.aes.DecryptBase64(encResp.Data)
	if err != nil {
		return nil, err
	}
	return Unpad(plainText), nil
}
