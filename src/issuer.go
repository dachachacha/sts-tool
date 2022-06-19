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
        "strings"
        "time"
        
        "github.com/golang-jwt/jwt/v4"
)

// Implement the 'issue' command
func IssueJwtCmd(args []string) {
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
	rttName := args[0]
        customClaims := args[1]

        log.Printf("rttName: %s\n",rttName)
        log.Printf("custom claims: %s\n", customClaims)
        
        /* Build claims */
        var mCustomClaims map[string]interface{}
        err = json.Unmarshal([]byte(customClaims), &mCustomClaims)
        if err != nil {
                die("Input is not valid JSON. err:  %v\n", err)
        }        
        signed := IssueJwt(rttName, mCustomClaims)
        fmt.Println(signed)
}

func IssueJwt (rttName string, customClaims map[string]interface{}) string {

        requestedTokenType := RequestedTokenType{}

        readRequestedTokenType(strings.Replace("../requested_token_types/{}.yml","{}",rttName,1), &requestedTokenType)
        rttUrn := requestedTokenType.Urn
        rttIssuer := requestedTokenType.Issuer 
        rttAudience := requestedTokenType.Audience

        log.Printf("rtt urn: %s\n",rttUrn)
        log.Printf("rtt issuer: %s\n",rttIssuer)
        log.Printf("rtt audience: %s\n",rttAudience)

        /* Get Issuer */
        issuer := Issuer{}
        readIssuer(strings.Replace("../issuers/{}.yml","{}",rttIssuer,1), &issuer)
        issuerUrn := issuer.Urn
        issuerKey := issuer.Key
        issuerAlg := issuer.Alg

        claims := jwt.MapClaims{}
        claims["iss"] = issuerUrn
        claims["aud"] = rttAudience
        claims["exp"] = time.Now().Add(time.Hour).Unix()
        for k, v := range customClaims { 
                claims[k] = v
        }

        log.Printf("issuer urn: %s\n",issuerUrn)
        //log.Printf("issuer key: %s\n",issuerKey)
        
        key := parseECPrivateKeyFromPEM(issuerKey,issuerAlg)
        method := jwt.GetSigningMethod(issuerAlg)
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

