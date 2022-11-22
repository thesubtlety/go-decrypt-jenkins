package jenkinscrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"unicode"
)

//https://github.com/jenkinsci/credentials-plugin/blob/master/src/main/java/com/cloudbees/plugins/credentials/CredentialsConfidentialKey.java#L150
func createcipherCredentialsConfidentialKey(sbk []byte, salt []byte) (cipher.BlockMode, error) {
	pwddigest := sbk
	pwddigest = append(pwddigest, salt...)
	keyAndIv := sha256.Sum256(pwddigest)

	key := make([]byte, 16)
	iv := make([]byte, 16)
	copy(key, keyAndIv[:16])
	copy(iv, keyAndIv[16:])

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("Error creating new cipher", err)
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)

	return mode, err
}

//Decryptsecretbytes decrypts jenkinsci SecretBytes encrypted with
//com.cloudbees.plugins.credentials.SecretBytes.KEY and master.key files
//https://github.com/jenkinsci/credentials-plugin/blob/master/src/main/java/com/cloudbees/plugins/credentials/SecretBytes.java#L130
func Decryptsecretbytes(secretbyteskey []byte, crypted string) (string, error) {
	if secretbyteskey == nil {
		return "", errors.New("no SecretBytes.key found")
	}
	if crypted == "" {
		return "", errors.New("received empty secretbytes string")
	}
	cryptedbytes, err := base64.StdEncoding.DecodeString(crypted[1 : len(crypted)-1])
	if err != nil {
		return "", err
	}

	saltsize := 8

	if crypted == "" || (len(cryptedbytes) < saltsize+1) {
		return "", errors.New("error decrypting, invalid string")
	}

	salt := cryptedbytes[:saltsize]
	padlength := cryptedbytes[saltsize]
	crypteddatalen := len(cryptedbytes) - saltsize - 1 - (int(padlength) & 0xff)
	crypteddata := cryptedbytes[saltsize+1 : (saltsize + 1 + crypteddatalen)]

	if len(cryptedbytes) < 16 {
		fmt.Println("Ciphertext too short")
		return "", err
	}

	if len(crypteddata)%16 != 0 {
		fmt.Println("Ciphertext is not a multiple of the block size")
		return "", err
	}

	mode, _ := createcipherCredentialsConfidentialKey(secretbyteskey, salt)
	mode.CryptBlocks(crypteddata, crypteddata)
	secret := crypteddata[:]

	decrypted := strings.TrimSpace(string(secret))
	decrypted = strings.TrimFunc(decrypted, func(r rune) bool {
		return !unicode.IsGraphic(r)
	})
	return decrypted, nil
}

//Initsecretbytesdecrypt takes in SecretBytes.KEY and master.key strings
//to read and decrypt returning a decrypted SecretBytes key
func Initsecretbytesdecrypt(secretbyteskeyfile string, mkeyfile string) []byte {
	secretbyteskey, err := ioutil.ReadFile(secretbyteskeyfile)
	if err != nil {
		fmt.Printf("error reading SecretBytes.KEY file '%s':%s\n", secretbyteskeyfile, err)
		os.Exit(1)
	}

	masterkey, err := ioutil.ReadFile(mkeyfile)
	if err != nil {
		fmt.Printf("error reading  master.key file '%s':%s\n", mkeyfile, err)
		os.Exit(1)
	}

	sbk, err := Decryptmasterkey(string(masterkey), secretbyteskey)
	if err != nil {
		fmt.Println("Error decrypting keys... ", err)
		os.Exit(1)
	}
	return sbk
}
