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

// reference
// https://web.archive.org/web/20190916195518/http://xn--thibaud-dya.fr/jenkins_credentials.html

//ECBDecrypt decrypts aes block without an iv
//https://stackoverflow.com/questions/50796912/java-aes-ecb-encryption-to-golang-migration
func ECBDecrypt(k, encrypted []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	if len(encrypted)%aes.BlockSize != 0 {
		return nil, err
	}
	decrypted := make([]byte, len(encrypted))
	size := 16

	for bs, be := 0, size; bs < len(encrypted); bs, be = bs+size, be+size {
		cipher.Decrypt(decrypted[bs:be], encrypted[bs:be])
	}

	return decrypted, nil
}

//Decryptv1 string given key from master.key and hudson.util.Secret (older Hudson/Jenkins)
func Decryptv1(k []byte, crypted string) (string, error) {
	if crypted == "" {
		return "", nil
	}

	cryptedbytes, err := base64.StdEncoding.DecodeString(crypted)
	if err != nil {
		return "", err
	}

	secret, err := ECBDecrypt(k, cryptedbytes)
	if err != nil {
		return "", err
	}

	magic := "::::MAGIC::::"
	if !strings.Contains(string(secret), magic) {
		return "", errors.New("unable to decrypt, no magic found in v1 secret")
	}
	secrets := strings.Replace(string(secret), magic, "", 1)

	decrypted := strings.TrimSpace(secrets)
	decrypted = strings.TrimFunc(decrypted, func(r rune) bool {
		return !unicode.IsGraphic(r)
	})
	return string(decrypted), nil
}

//Decrypt string given key from master.key and hudson.util.Secret
func Decrypt(k []byte, crypted string) (string, error) {
	if crypted == "" || len(crypted) < 8 {
		return "", nil
	}

	cryptedbytes, err := base64.StdEncoding.DecodeString(crypted[1 : len(crypted)-1])
	if err != nil {
		return "", err
	}

	ivlength := (cryptedbytes[4] & 0xff)
	if int(ivlength) > len(cryptedbytes) {
		return "", errors.New("invalid encrypted string")
	}

	cryptedbytes = cryptedbytes[1:] //Strip the version
	cryptedbytes = cryptedbytes[4:] //Strip the iv length
	cryptedbytes = cryptedbytes[4:] //Strip the data length

	iv := cryptedbytes[:ivlength]
	cryptedbytes = cryptedbytes[ivlength:]

	block, err := aes.NewCipher(k)
	if err != nil {
		fmt.Println("Error creating new cipher", err)
		return "", err
	}
	if len(cryptedbytes) < aes.BlockSize {
		fmt.Println("Ciphertext too short")
		return "", err
	}
	if len(cryptedbytes)%aes.BlockSize != 0 {
		fmt.Println("Ciphertext is not a multiple of the block size")
		return "", err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cryptedbytes, cryptedbytes)

	decrypted := strings.TrimSpace(string(cryptedbytes))
	decrypted = strings.TrimFunc(decrypted, func(r rune) bool {
		return !unicode.IsGraphic(r)
	})
	return decrypted, nil
}

//Decryptmasterkey returns a key given a master.key file and hudson.util.Secret file
func Decryptmasterkey(masterkey string, encsecretkeyfile []byte) ([]byte, error) {
	hashedmasterkey := sha256.Sum256([]byte(masterkey))

	secret, err := ECBDecrypt(hashedmasterkey[:16], encsecretkeyfile)
	if err != nil {
		return nil, err
	}

	if !strings.Contains(string(secret), ":::MAGIC:::") {
		return nil, errors.New("unable to decrypt, no magic found in hudson.util.Secret")
	}
	secret = secret[:16]
	return secret, nil
}

//Initdecrypt takes in hudson.util.Secret and master.key strings
//to read and decrypt returning a decrypted hudson.util.Secret key
func Initdecrypt(hsecretfile string, mkeyfile string) []byte {

	hudsonsecret, err := ioutil.ReadFile(hsecretfile)
	if err != nil {
		fmt.Printf("error reading hudson.util.Secret file '%s':%s\n", hsecretfile, err)
		os.Exit(1)
	}

	masterkey, err := ioutil.ReadFile(mkeyfile)
	if err != nil {
		fmt.Printf("error reading master.key file '%s':%s\n", mkeyfile, err)
		os.Exit(1)
	}

	k, err := Decryptmasterkey(string(masterkey), hudsonsecret)
	if err != nil {
		fmt.Println("Error decrypting keys... ", err)
		os.Exit(1)
	}
	return k
}
