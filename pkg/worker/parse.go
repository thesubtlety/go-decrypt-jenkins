package worker

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/beevik/etree"
	"github.com/thesubtlety/go-decrypt-jenkins/pkg/jenkinscrypto"
)

func getidanduser(cf []byte) (string, string) {
	var id, name string
	rid := regexp.MustCompile("<id>(.*?)</id>").FindStringSubmatch(string(cf))
	if len(rid) > 0 {
		id = rid[1]
	}
	rname := regexp.MustCompile("<fullName>(.*?)</fullName>").FindStringSubmatch(string(cf))
	if len(rname) > 0 {
		name = rname[1]
	}
	return id, name
}

func checkversion(s string) string {
	s = strings.Replace(s, "{", "", 1)
	s = strings.Replace(s, "}", "", 1)
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}

	switch b[0] {
	case 1:
		return "new"
	default:
		return "old"
	}
}

func trydecrypt(k []byte, sbk []byte, tag string, val string) (string, error) {
	var decrypted string
	var err error
	ver := checkversion(val)

	if tag == "secretBytes" {
		decrypted, err := jenkinscrypto.Decryptsecretbytes(sbk, val)
		if err != nil {
			return "", err
		}
		return decrypted, nil
	}

	if tag == "apiToken" {
		switch ver {
		case "new":
			decrypted, err = jenkinscrypto.Decrypt(k, val)
			if err != nil {
				return "", err
			}
		default:
			decrypted, err = jenkinscrypto.Decryptv1(k, val)
			if err != nil {
				return "", err
			}
		}

		apitokenmd5 := md5.Sum([]byte(decrypted)[:16])
		apitoken := fmt.Sprintf("%x", string(apitokenmd5[:16]))
		return apitoken, nil
	}

	switch ver {
	case "new":
		decrypted, err := jenkinscrypto.Decrypt(k, val)
		if err != nil {
			return "", err
		}
		return decrypted, nil
	default: //only try to decrypt old format if it's interesting to reduce false positives
		ok, _ := regexp.Match(`/pass|secret|private|token|key|auth/i`, []byte(tag))
		if !ok {
			return val, nil
		}
		decrypted, err := jenkinscrypto.Decryptv1(k, val)
		if err != nil {
			return "", err
		}
		return decrypted, nil
	}
}

//Parsefile takes in key material, a file, and tries to decrypt values
func Parsefile(k []byte, sbk []byte, credfile []byte) {
	cf, err := ioutil.ReadAll(bytes.NewReader(credfile))
	if err != nil {
		fmt.Println("Unable to read file", err)
		return
	}

	//awful awful hack to get around only 1.0 being supported by etree
	cfs := strings.Replace(string(cf), "version='1.1'", "version='1.0'", 1)

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes([]byte(cfs)); err != nil {
		return
	}

	for _, plugin := range Plugins {
		elements := doc.FindElements("//" + plugin)

		for _, el := range elements {
			printseparator := false
			elementinfo := gettokensfromnode(el)

			if len(elementinfo) < 1 {
				continue
			}

			for tag, v := range elementinfo {
				v = strings.TrimSpace(v)
				if v == "" {
					continue
				}
				printseparator = true

				if plugin == "scm[@class='hudson.plugins.perforce.PerforceSCM']" {
					if !strings.HasPrefix(tag, "p4") {
						continue
					}
				}

				if tag == "apiToken" {
					id, name := getidanduser(cf)
					if id != "" {
						fmt.Printf("id: %s\n", id)
					}
					if name != "" {
						fmt.Printf("name: %s\n", name)
					}
				}

				if tag == "passwordHash" {
					id, name := getidanduser(cf)
					if id != "" {
						fmt.Printf("id: %s\n", id)
					}
					if name != "" {
						fmt.Printf("name: %s\n", name)
					}
					fmt.Printf("%s: %s\n", tag, v)
					continue
				}

				decrypted, err := trydecrypt(k, sbk, tag, v)
				if err != nil {
					fmt.Printf("%s: %s\n", tag, string(err.Error()))
					continue
				}

				fmt.Printf("%s: %s\n", tag, decrypted)
			}
			if printseparator {
				fmt.Println("")
				printseparator = false
			}
		}
	}
}
