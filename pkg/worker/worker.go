package worker

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/thesubtlety/go-decrypt-jenkins/pkg/config"
	"github.com/thesubtlety/go-decrypt-jenkins/pkg/jenkinscrypto"
)

//DefaultParse tries to decrypt a given xml file given the passed in decryption keys from the command line
func DefaultParse() {
	var sbk []byte
	if config.Secretbytesfile != "" {
		sbk = jenkinscrypto.Initsecretbytesdecrypt(config.Secretbytesfile, config.Masterkeyfile)
	}
	k := jenkinscrypto.Initdecrypt(config.Secretkeyfile, config.Masterkeyfile)

	f, err := ioutil.ReadFile(config.Credfile)
	if err != nil {
		fmt.Println("Unable to read file", err)
		return
	}
	Parsefile(k, sbk, f)
}

//Brute takes a given a file and a key, regex parse {.+} and try to decrypt values
func Brute(k []byte) {

	if config.Credfile == "" {
		fmt.Println("No cred file file found")
		return
	}

	cf, err := ioutil.ReadFile(config.Credfile)
	if err != nil {
		fmt.Println("Unable to read file", err)
		return
	}

	re, err := regexp.Compile(`{.+}`)
	if err != nil {
		fmt.Println("No encrypted values found")
		return
	}

	matches := re.FindAll(cf, -1)
	var decrypted string
	for _, v := range matches {
		if config.Secretbytesfile != "" {
			decrypted, _ = jenkinscrypto.Decryptsecretbytes(k, string(v))
		} else {
			decrypted, _ = jenkinscrypto.Decrypt(k, string(v))
		}
		decrypted = strings.TrimFunc(decrypted, func(r rune) bool {
			return !unicode.IsGraphic(r)
		})
		if len(decrypted) > 0 {
			fmt.Printf("\n%s\n", decrypted)
		}
	}
}

//Search reads the path found in config.Search dir, walks the dir for
//xml files and tries to decrypt encrypted creds if key material is found
func Search() {
	fmt.Println("Searching for files in", config.Searchdirectory)
	if _, err := os.Stat(config.Searchdirectory); err != nil {
		fmt.Println(err)
		return
	}

	var k []byte
	var sbk []byte

	if config.Secretkeyfile != "" && config.Masterkeyfile != "" {
		k = jenkinscrypto.Initdecrypt(config.Secretkeyfile, config.Masterkeyfile)
	}

	if config.Secretbytesfile != "" && config.Masterkeyfile != "" {
		sbk = jenkinscrypto.Initsecretbytesdecrypt(config.Secretbytesfile, config.Masterkeyfile)
	}

	var files []string
	_ = filepath.Walk(config.Searchdirectory, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})

	var xmlfiles []string
	for _, f := range files {
		if strings.HasSuffix(f, "master.key") {
			if config.Masterkeyfile == "" {
				config.Masterkeyfile = f
			}
		}
		if strings.HasSuffix(f, "hudson.util.Secret") {
			if config.Secretkeyfile == "" {
				config.Secretkeyfile = f
			}
		}
		if strings.HasSuffix(f, "com.cloudbees.plugins.credentials.SecretBytes.KEY") {
			if config.Secretbytesfile == "" {
				config.Secretbytesfile = f
			}
		}
		if strings.HasSuffix(f, ".xml") {
			xmlfiles = append(xmlfiles, f)
		}
	}

	if config.Masterkeyfile == "" {
		fmt.Println("No master.key or hudson.util.Secret found, exiting...")
		return
	}

	if sbk == nil && config.Secretbytesfile != "" {
		sbk = jenkinscrypto.Initsecretbytesdecrypt(config.Secretbytesfile, config.Masterkeyfile)
	}

	if k == nil && config.Secretkeyfile != "" {
		k = jenkinscrypto.Initdecrypt(config.Secretkeyfile, config.Masterkeyfile)
	}

	for _, xmlfile := range xmlfiles {
		if config.Optionbrute {
			//such a hack
			config.Credfile = xmlfile
			Brute(k)
		} else {
			f, err := ioutil.ReadFile(xmlfile)
			if err != nil {
				fmt.Println("Unable to read file", err)
				return
			}
			Parsefile(k, sbk, f)
		}
	}
}
