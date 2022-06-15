// issuer.go 
//

package main

import (
        "flag"
        "fmt"
        "io/ioutil"
        "log"
        "os"
        //"strings"
        
        "github.com/golang-jwt/jwt/v4"
        "gopkg.in/yaml.v3"
)

type Issuer struct {
        Urn string `yaml:"urn"`
        Key string `yaml:"key"`
}

// Implement the 'issue' command
func IssueJwt(args []string) {
	fs := flag.NewFlagSet("issuer", flag.ExitOnError)
	fs.Usage = func() {
		issueUsage(fs)
	}

        err := fs.Parse(args)
        if err != nil {
                die("%s", err)
        }
	args = fs.Args()
	if len(args) < 1 {
		warn("Insufficient arguments to 'issue'\n")
		fs.Usage()
	}
	issuerName := args[0]
        fmt.Printf("issuer name: %s\n",issuerName)

        issuer := Issuer{}

        ymlFile, err := ioutil.ReadFile("../issuers/issuer_001.yml")
        if err != nil {
                log.Fatalf("ca.yml err:   #%v ", err)
        }
        err = yaml.Unmarshal(ymlFile, &issuer)
        urn := issuer.Urn
        key := issuer.Key
        fmt.Printf("issuer urn: %s\n",urn)
        fmt.Printf("issuer key: %s\n",key)
        
        ecdsaKey, err := jwt.ParseECPrivateKeyFromPEM([]byte(key)) 
        if err != nil {
                fmt.Printf("Unable to parse ECDSA private key: %v\n", err)
        }
        method := jwt.GetSigningMethod("ES256")
        token := jwt.NewWithClaims(method,jwt.StandardClaims{
                Audience: "bar",
                Issuer: issuer.Urn,
        })
        signed, err := token.SignedString(ecdsaKey)
        if err != nil {
                panic(err)
        }
        fmt.Println(signed)
}

func issueUsage(fs *flag.FlagSet) {
	fmt.Printf(`%s issue: Issue a new issuer JWT

Usage: %s issuer [options] issuer-urn

Where 'issuer-urn' is the URN of the issuer.

Options:
`, os.Args[0], os.Args[0])

	fs.PrintDefaults()
	os.Exit(0)
}

