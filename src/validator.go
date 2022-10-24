// validator.go 
//

package main

import (
        //"crypto/ecdsa"
        //"encoding/json"
        "flag"
        "fmt"
        "log"
        "os"
        "strings"
//        "time"
        
        "github.com/golang-jwt/jwt/v4"
)

// Implement the 'validate' command
func ValidateJwtCmd(args []string) {
    log.SetPrefix("[validator] - ")

	fs := flag.NewFlagSet("validator", flag.ExitOnError)
	fs.Usage = func() {
		validateUsage(fs)
	}

        err := fs.Parse(args)
        if err != nil {
                die("%s", err)
        }
	args = fs.Args()
	if len(args) < 2 {
		warn("Insufficient arguments to 'validate'\n")
		fs.Usage()
	}
	inputJwt := args[0]
        subjectTokenTypeUrn := args[1]

        log.Printf("inputJwt: %s\n",inputJwt)
        log.Printf("SubjectTokenTypeUrn: %s\n", subjectTokenTypeUrn)
        
        validation := ValidateJwtFromSubjectTokenType(inputJwt, subjectTokenTypeUrn)
        fmt.Println(validation)
}

func ValidateJwtFromSubjectTokenType (inputJwt string, subjectTokenTypeUrn string) bool {

        subjectTokenType := SubjectTokenType{}

        readSubjectTokenType(strings.Replace("../subject_token_types/{}.yml","{}",subjectTokenTypeUrn,1), &subjectTokenType)
        sttUrn := subjectTokenType.Urn
        sttValidator := subjectTokenType.Validator 
        sttAudience := subjectTokenType.Audience
        sttIssuer := subjectTokenType.Issuer

        log.Printf("stt urn: %s\n",sttUrn)
        log.Printf("stt validator: %s\n",sttValidator)
        log.Printf("stt audience: %s\n",sttAudience)

        /* Get Validator */
        validator := Validator{}
        readValidator(strings.Replace("../validators/{}.yml","{}",sttValidator,1), &validator)
        validatorUrn := validator.Urn
        validatorCert := validator.Cert
        validatorAlg := validator.Alg

        log.Printf("validator urn: %s\n",validatorUrn)
        log.Printf("validator cert: %s\n",validatorCert)
        log.Printf("validator alg: %s\n",validatorAlg)

        key := parseECPublicKeyFromCertPEM(validatorCert,validatorAlg)
        log.Printf("parsed public Key: %v\n",key)
        //method := jwt.GetSigningMethod(validatorAlg)
        //claims := jwt.MapClaims{}
        token, err := jwt.Parse(inputJwt, func(token *jwt.Token) (interface{}, error) {
                return key, nil
        })
        if err != nil {
                log.Fatalf("Error parsing JWT: %v",err)
                return false
        }
        check := token.Claims.(jwt.MapClaims).VerifyAudience(sttAudience,true)
        if ! check {
            log.Fatalf("Invalid audience.")
        }
        log.Printf("audience verified")
        check = token.Claims.(jwt.MapClaims).VerifyIssuer(sttIssuer,true)
        if ! check {
            log.Fatalf("Invalid issuer.")
        }
        log.Printf("issuer verified")
        return true
}

func ValidateJwtWithCert(inputJwt string, pem string, alg string) (jwt.MapClaims,error) {
    key := parseECPublicKeyFromCertPEM(pem,alg)
    token, err := jwt.Parse(inputJwt, func(token *jwt.Token) (interface{}, error) {
                    return key, nil
                })
    if err != nil {
        log.Printf("Error parsing Authenticating JWT: %v",err)
        return nil, err
    }
    log.Printf("Successfully validated token")
    return token.Claims.(jwt.MapClaims), nil
}

func ParseJwtNoVerify(tokenString string) (jwt.MapClaims, []string, error) {
    claims := jwt.MapClaims{}
    token, parts, err := new(jwt.Parser).ParseUnverified(tokenString,claims)
    if err != nil {
        return nil, nil, err
    }
    return token.Claims.(jwt.MapClaims), parts, err
}

func validateUsage(fs *flag.FlagSet) {
	fmt.Printf(`%s validate: Validate a new JWT

Usage: %s validate [options] input-jwt subject-token-type-urn

Options:
`, os.Args[0], os.Args[0])

	fs.PrintDefaults()
	os.Exit(0)
}

