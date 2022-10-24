package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "net/http"
    "os"
//    "reflect"
    "strings"
    "time"
    
    "github.com/gorilla/context"
    "github.com/gorilla/mux"
    "github.com/golang-jwt/jwt/v4"
    "golang.org/x/exp/slices"
)

type StsRequest struct {
    SubjectToken string
    SubjectTokenType string
    Audience string
    RequestedTokenType string
    GrantType string
}

type StsResponse struct {
    AccessToken string
    IssuedTokenType string
    TokenType string
    ExpiresIn int
}
func isAllowedAudience(client *Client, audience string) bool {
    log.Printf("Checking if the client is authorized for the audience: %s", audience)
    return slices.Contains(client.AllowedAudiences, audience)
}
func isAllowedStsRequest(client *Client, subjectTokenType string, requestedTokenType string) bool {
    log.Printf("Checking if the client is authorized for '%s' and '%s'", subjectTokenType, requestedTokenType)
    allowed := client.AllowedStsRequests
    found := false;
    for _, v := range allowed {
        if v.SubjectTokenType == subjectTokenType && v.RequestedTokenType == requestedTokenType {
            found = true
            break
        } 
    }
    return found
}
func ValidateSubjectToken(subjectToken string) (jwt.MapClaims, error) {
    claims, _, err := ParseJwtNoVerify(subjectToken)
    if err != nil {
        log.Printf("Error verifying Subject Token: %s\n", err)
        return nil, err
    }
    log.Printf("claims: %v",claims)
    log.Printf("issuer: %s", claims["iss"])
    validator, err := GetValidatorFromDB(claims["iss"].(string))
    if err != nil {
        log.Printf("Error verifying subject token: %s\n", err)
        return nil, err
    }
    log.Printf("Extracted validator: %s", validator.Urn)
    claims, err = ValidateJwtWithCert(subjectToken, validator.Cert, validator.Alg)
    if err != nil {
        log.Printf("Could not validate Subject Token with Cert: %v\n", err)
        return nil, err
    }
    return claims, nil
}
func exchangeToken(w http.ResponseWriter, r *http.Request) {
    stsReq := &StsRequest {
        SubjectToken: r.PostFormValue("subject_token"),
        SubjectTokenType: r.PostFormValue("subject_token_type"),
        Audience: r.PostFormValue("audience"),
        RequestedTokenType: r.PostFormValue("requested_token_type"),
        GrantType: r.PostFormValue("grant_type"),
    }
    log.Printf("subject_token: " + stsReq.SubjectToken)
    log.Printf("subject_token_type: " + stsReq.SubjectTokenType)
    log.Printf("audience: " + stsReq.Audience)
    log.Printf("requested_token_type: " + stsReq.RequestedTokenType)
    log.Printf("grant_type: " + stsReq.GrantType)
    if stsReq.SubjectToken == "" || stsReq.SubjectTokenType == "" || stsReq.Audience == "" || stsReq.RequestedTokenType == "" || stsReq.GrantType == ""  {
        log.Printf("All token exchange fields are mandatory")
        http.Error(w, "Bad Request.", http.StatusBadRequest)
        return
    }
    client := context.Get(r, "client").(*Client)
    check := isAllowedAudience(client, stsReq.Audience)
    if ! check {
        log.Printf("Audience check failed")
        http.Error(w, "Forbidden.", http.StatusForbidden)
        return
    }
    check = isAllowedStsRequest(client, stsReq.SubjectTokenType, stsReq.RequestedTokenType)
    if ! check {
        log.Printf("Client is not allowed to perform this exchange (not in `allowed_sts_requests`)")
        http.Error(w, "Forbidden.", http.StatusForbidden)
        return
    }
    subjectTokenClaims, err := ValidateSubjectToken(stsReq.SubjectToken)
    if err != nil {
        log.Printf("Subject token could not be validated")
        http.Error(w, "Forbidden.", http.StatusForbidden)
        return
    }
    requestedTokenType, err := GetRequestedTokenTypeFromDB(stsReq.RequestedTokenType)
    if err != nil {
        log.Printf("requested_token_type could not be found in the claims")
        http.Error(w, "Forbidden.", http.StatusForbidden)
        return
    }
    log.Printf("requested token type object: %v\n", requestedTokenType)
    respClaims := jwt.MapClaims{}
    var nonInheritableClaims  = []string{"iat","nbf","exp","aud","iss"} 
    foundSub := false
    for k := range subjectTokenClaims {
        if ! slices.Contains(nonInheritableClaims, k) {
            respClaims[k] = subjectTokenClaims[k]
        }
        if k == "sub" {
            foundSub = true
        }
    }
    if (! foundSub) {
        log.Printf("didn't find 'sub' in the claims")
        http.Error(w, "Forbidden.", http.StatusForbidden)
        return
    }
    respIssuer, err := GetIssuerFromDB(requestedTokenType.Issuer)
    respClaims["iss"] = requestedTokenType.Issuer
    respClaims["aud"] = requestedTokenType.Audience
    exp := time.Now().Local().Add(time.Second * time.Duration(respIssuer.Lifetime)).Unix()
    log.Printf("expiry: %v\n", exp)
    log.Printf("issuer.Lifetime: %v\n", respIssuer.Lifetime)
    respClaims["iat"] = time.Now().Local().Unix()
    respClaims["exp"] = exp
    log.Printf("respClaims: %v\n", respClaims)
    log.Printf("Issuer used for output token: %s\n", respIssuer.Urn)
    newToken, err := IssueJwtFromIssuer(respClaims, respIssuer)
    log.Printf("New AccessToken generated: %s\n", newToken)
    stsResponse := &StsResponse{}
    stsResponse.AccessToken = newToken
    stsResponse.IssuedTokenType = "urn:ietf:params:oauth:token-type:access_token"
    stsResponse.TokenType = "Bearer"
    stsResponse.ExpiresIn = 3600
    jsonResponse, jsonError := json.Marshal(stsResponse)
    if jsonError != nil {
        fmt.Println("Unable to encode JSON")
    }

    fmt.Println(string(jsonResponse))

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    w.Write(jsonResponse)
    }

func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

        tokenString := r.Header.Get("Authorization")
        if len(tokenString) == 0 {
            log.Printf("Missing Authorization Header\n")
            http.Error(w, "Access Denied.", http.StatusUnauthorized)
            return
        }
        tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
        claims, _, err := ParseJwtNoVerify(tokenString)
        if err != nil {
            log.Printf("Error verifying JWT token: %s\n", err)
            http.Error(w, "Access Denied.", http.StatusUnauthorized)
            return
        }
        log.Printf("issuer: %s", claims["iss"])
        authenticator, err := GetAuthenticatorFromDB(claims["iss"].(string))
        if err != nil {
            log.Printf("Authenticator not found in DB for given issuer: %s\n", claims["iss"].(string))
            http.Error(w, "Access Denied.", http.StatusUnauthorized)
            return
        }
        log.Printf("authenticator: %s", *authenticator)
        _, err = ValidateJwtWithCert(tokenString, authenticator.Cert, authenticator.Alg)
        if err != nil {
            log.Printf("Could not validate JWT with Cert: %v\n", err)
            http.Error(w, "Access Denied.", http.StatusUnauthorized)
            return
        }
        if claims["sub"] == nil {
            log.Printf("'sub' claim absent in JWT")
            http.Error(w, "Access Denied.", http.StatusUnauthorized)
            return
        }
        client, err := GetClientFromDB(claims["sub"].(string))
        if err != nil {
            log.Printf("User could not be retrieved form DB: %v", err)
            http.Error(w, "Access Denied.", http.StatusUnauthorized)
            return
        }
        log.Printf("successfully authenticated user: %s", client.Urn)
        context.Set(r, "client", client)
        next.ServeHTTP(w, r)
    })
}

func validate() {
}
func issue() {
}
func issuer(w http.ResponseWriter, r *http.Request) {
}
func validator(w http.ResponseWriter, r *http.Request) {
}
func authenticator(w http.ResponseWriter, r *http.Request) {
}
func requested_token_type(w http.ResponseWriter, r *http.Request) {
}
func subject_token_type(w http.ResponseWriter, r *http.Request) {
}
func clients(w http.ResponseWriter, r *http.Request) {
}

func ServerCmd(args []string) {
    log.SetPrefix("[server] - ")

    runServer()

}

func runServer() {
    r := mux.NewRouter()
    r.HandleFunc("/token", exchangeToken).Methods("POST")

    r.HandleFunc("/issuer",issuer)
    r.HandleFunc("/validator",validator)
    r.HandleFunc("/authenticator",authenticator)
    r.HandleFunc("/requested_token_type",requested_token_type)
    r.HandleFunc("/subject_token_type",subject_token_type)
    r.HandleFunc("/clients",clients)
    srv := &http.Server{
        Handler:      r,
        Addr:         "127.0.0.1:8000",
        // Good practice: enforce timeouts for servers you create!
        WriteTimeout: 15 * time.Second,
        ReadTimeout:  15 * time.Second,
    }
    r.Use(authMiddleware)
    log.Fatal(srv.ListenAndServe())
}

func serverUsage(fs *flag.FlagSet) {
    fmt.Printf(`%s server: run the STS server

Usage: %s server [options]

Options:
`, os.Args[0], os.Args[0])

    fs.PrintDefaults()
    os.Exit(0)
}
