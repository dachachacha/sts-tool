package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "net/http"
    "os"
    "reflect"
    "strings"
    "time"
    
    "github.com/gorilla/mux"
    "github.com/golang-jwt/jwt/v4"
)


func exchange2(w http.ResponseWriter, r *http.Request) {
    //log.Printf("%v",r)
    if r.Method != "POST" {
        http.Error(w, "bad request.", http.StatusBadRequest)
        return
    }
    if err := r.ParseForm(); err != nil {
        fmt.Fprintf(w, "ParseForm() err: %v", err)
        return
    }
    subject_token := r.FormValue("subject_token")
    subject_token_type := r.FormValue("subject_token_type")    
    audience := r.FormValue("audience")    
    requested_token_type := r.FormValue("requested_token_type") 
    grant_type := r.FormValue("grant_type") 
    log.Printf("subject_token: " + subject_token)
    log.Printf("subject_token_type: " + subject_token_type)
    log.Printf("audience: " + audience)
    log.Printf("requested_token_type: " + requested_token_type)
    log.Printf("grant_type: " + grant_type)
}

func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

        tokenString := r.Header.Get("Authorization")
        if len(tokenString) == 0 {
            w.WriteHeader(http.StatusUnauthorized)
            w.Write([]byte("Missing Authorization Header"))
            return
        }
        tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
        claims, _, err := parseTokenNoVerify(tokenString)
        if err != nil {
            w.WriteHeader(http.StatusUnauthorized)
            w.Write([]byte("Error verifying JWT token: " + err.Error()))
            return
        }
        log.Printf("claims: %v",claims)
        log.Printf("issuer: %s", reflect.TypeOf(claims))
        log.Printf("issuer: %s", claims["iss"])
        next.ServeHTTP(w, r)
    })
}

func parseToken(tokenString string) (jwt.Claims,  error) {
    claims := jwt.MapClaims{}
    token, _, err := new(jwt.Parser).ParseUnverified(tokenString,claims)
    if err != nil {
        return nil, err
    }
    return token.Claims, err
}

func parseTokenNoVerify(tokenString string) (jwt.MapClaims, []string, error) {
    claims := jwt.MapClaims{}
    token, parts, err := new(jwt.Parser).ParseUnverified(tokenString,claims)
    if err != nil {
        return nil, nil, err
    }
    return token.Claims.(jwt.MapClaims), parts, err
}

func JwtVerify(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        var header = r.Header.Get("Authorization")

        json.NewEncoder(w).Encode(r)
        header = strings.TrimSpace(header)

        if header == "" {
            w.WriteHeader(http.StatusForbidden)
            json.NewEncoder(w).Encode("Missing auth token")
            return
        } else {
            json.NewEncoder(w).Encode(fmt.Sprintf("Token found. Value %s", header))
        }
        next.ServeHTTP(w, r)
    })
}

func exchange(w http.ResponseWriter, r *http.Request) {
    return
}

func ServerCmd(args []string) {

    runServer()

}

func runServer() {
    r := mux.NewRouter()
    r.HandleFunc("/token", exchange)
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
