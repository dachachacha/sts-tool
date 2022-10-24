// issuer.go 
//

package main

import (
    //"crypto/ecdsa"
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "os"
//    "strings"
    "time"
    
    "github.com/golang-jwt/jwt/v4"
)

// Implement the 'issue' command
func IssueJwtCmd(args []string) {
    log.SetPrefix("[issuer] - ")

	fs := flag.NewFlagSet("issuer", flag.ExitOnError)
	fs.Usage = func() {
		issueUsage(fs)
	}

    err := fs.Parse(args)
    if err != nil {
        die("%s", err)
    }
	args = fs.Args()
	if len(args) < 2 {
		warn("Insufficient arguments to 'issue'\n")
		fs.Usage()
	}
	inputRttUrn := args[0]
    customClaims := args[1]

    log.Printf("inputRttUrn: %s\n", inputRttUrn)
    log.Printf("custom claims: %s\n", customClaims)
    
    /* Build claims */
    var mCustomClaims map[string]interface{}
    err = json.Unmarshal([]byte(customClaims), &mCustomClaims)
    if err != nil {
        die("Input is not valid JSON. err:  %v\n", err)
    }    
    signed := IssueJwt(inputRttUrn, mCustomClaims)
    fmt.Println(signed)
}

func IssueJwtFromIssuer(claims jwt.MapClaims, issuer *Issuer) (string, error) {
    key := parseECPrivateKeyFromPEM(issuer.Key,issuer.Alg)
    method := jwt.GetSigningMethod(issuer.Alg)
    log.Printf("%v\n",claims)
    token := jwt.NewWithClaims(method,claims)
    signed, err := token.SignedString(key)
    if err != nil {
        log.Printf("Problem generating JWT")
        return "", err
    }
    return signed, nil
}

func IssueJwt (inputRttUrn string, customClaims map[string]interface{}) string {

    requestedTokenType, err := GetRequestedTokenTypeFromDB(inputRttUrn)
    if err != nil {
        log.Fatalf("Could not retrieve requested token type from DB")
    }
    rttUrn := requestedTokenType.Urn
    rttIssuerUrn := requestedTokenType.Issuer
    rttAudience := requestedTokenType.Audience

    log.Printf("rtt urn: %s\n",rttUrn)
    log.Printf("rtt issuer: %s\n",rttIssuerUrn)
    log.Printf("rtt audience: %s\n",rttAudience)

    /* Get Issuer */
    issuer, err := GetIssuerFromDB(rttIssuerUrn)
    if err != nil {
        log.Fatalf("Could not retrieve issuer from DB")
    }

    claims := jwt.MapClaims{}
    claims["iss"] = issuer.Urn
    claims["aud"] = rttAudience
    claims["exp"] = time.Now().Add(time.Minute * time.Duration(issuer.Lifetime)).Unix()
    for k, v := range customClaims { 
        claims[k] = v
    }

    log.Printf("issuer urn: %s\n", issuer.Urn)
    //log.Printf("issuer key: %s\n",issuerKey)
    
    key := parseECPrivateKeyFromPEM(issuer.Key,issuer.Alg)
    method := jwt.GetSigningMethod(issuer.Alg)
    log.Printf("%v\n",claims)
    token := jwt.NewWithClaims(method,claims)
    signed, err := token.SignedString(key)
    if err != nil {
        die("Error signing JWT: %v",err)
    }
    return signed
}

func issueUsage(fs *flag.FlagSet) {
	fmt.Printf(`%s issue: Issue a new JWT

Usage: %s issue [options] requested-token-type-urn custom-claims

Options:
`, os.Args[0], os.Args[0])

	fs.PrintDefaults()
	os.Exit(0)
}

