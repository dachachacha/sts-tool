package main

import (
        //"crypto/x509"
        "flag"
        "fmt"
        "log"
        "os"
        "path"
        "path/filepath"
        "strings"
        "github.com/opencoff/go-utils"
        "github.com/hashicorp/go-memdb"
)

var config Config;
var db *memdb.MemDB;

func main() {
        flag.Usage = func() {
                fmt.Printf(
                        `%s - STS Tool

Usage: %s CONFIG-DIR CMD [args..]

Where 'CMD' is one of:

    issue            issue a new token
    validate         validate a token
    server           run the STS server
    authenticate     authenticate token
    enrich           enrich a token with new claims

`, path.Base(os.Args[0]), os.Args[0])
                flag.PrintDefaults()
                os.Stdout.Sync()
                os.Exit(0)
        }
        flag.Parse()
        args := flag.Args()

        if len(args) < 2 {
                die("Insufficient arguments!\nTry '%s -h'\n", os.Args[0])
        }
        
        var cmds = map[string]func([]string){
                "issue":            IssueJwtCmd,
                "validate":         ValidateJwtCmd,
                "server":           ServerCmd,
                /*"validate":         ValidateJwt,
                "authenticate":     AuthenticateJwt,
                "enrich":           EnrichJwt,*/
        }

        words := make([]string, len(cmds))
        for k := range cmds {
                words = append(words, k)
        }
        ab := utils.Abbrev(words)

        configDir := strings.ToLower(args[0])
        log.Printf("Config Directory: %s\n", configDir)

        config = Config{
            Authenticators: filepath.Join(configDir,"authenticators"),
            Clients: filepath.Join(configDir,"clients"),
            Issuers: filepath.Join(configDir,"issuers"),
            RequestedTokenTypes: filepath.Join(configDir,"requested_token_types"),
            SubjectTokenTypes: filepath.Join(configDir,"subject_token_types"),
            Validators: filepath.Join(configDir,"validators"),
        }

        db = CreateDB([]string{"authenticator","client","issuer","requested_token_type","subject_token_type","validator"})
        //issuer := Issuer{}
        //loadIssuers(config.Issuers)
        loadData(config.Authenticators,"authenticator",CreateAuthenticator)
        loadData(config.Issuers,"issuer",CreateIssuer)
        loadData(config.Clients,"client",CreateClient)
        loadData(config.RequestedTokenTypes,"requested_token_type",CreateRequestedTokenType)
        loadData(config.SubjectTokenTypes,"subject_token_type",CreateSubjectTokenType{})
        loadData(config.Validators,"validator",CreateValidator)

        cmd := strings.ToLower(args[1])
        canon, ok := ab[cmd]
        if !ok {
                die("unknown command '%s'; Try '%s --help'", cmd, os.Args[0])
        }

        fp, ok := cmds[canon]
        if !ok {
                die("can't map command '%s'", canon)
        }

        fp(args[2:])
        
}
