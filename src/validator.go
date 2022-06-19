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
        
        validation := ValidateJwt(inputJwt, subjectTokenTypeUrn)
        fmt.Println(validation)
}

func ValidateJwt (inputJwt string, subjectTokenTypeUrn string) bool {

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

func validateUsage(fs *flag.FlagSet) {
	fmt.Printf(`%s validate: Validate a new JWT

Usage: %s validate [options] input-jwt subject-token-type-urn

Options:
`, os.Args[0], os.Args[0])

	fs.PrintDefaults()
	os.Exit(0)
}

