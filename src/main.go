package main

import (
        //"crypto/x509"
        "flag"
        "fmt"
        "os"
        "path"
        "strings"
        "github.com/opencoff/go-utils"

)

func main() {
        flag.Usage = func() {
                fmt.Printf(
                        `%s - Opinionated OpenVPN cert tool

Usage: %s [options] DB CMD [args..]

Where 'DB' points to the certificate database, and 'CMD' is one of:

    issue            issue a new token
    validate         validate a token
    authenticate     authenticate token
    enrich           enrich a token with new claims
    passwd           Change the DB encryption password

Options:
`, path.Base(os.Args[0]), os.Args[0])
                flag.PrintDefaults()
                os.Stdout.Sync()
                os.Exit(0)
        }
        flag.Parse()
        args := flag.Args()
        if len(args) < 1 {
                die("Insufficient arguments!\nTry '%s -h'\n", os.Args[0])
        }
        
        var cmds = map[string]func([]string){
                "issue":            IssueJwtCmd,
                "validate":         ValidateJwtCmd,
                /*"validate":         ValidateJwt,
                "authenticate":     AuthenticateJwt,
                "enrich":           EnrichJwt,*/
        }

        words := make([]string, len(cmds))
        for k := range cmds {
                words = append(words, k)
        }
        ab := utils.Abbrev(words)

        cmd := strings.ToLower(args[0])
        canon, ok := ab[cmd]
        if !ok {
                die("unknown command '%s'; Try '%s --help'", cmd, os.Args[0])
        }

        fp, ok := cmds[canon]
        if !ok {
                die("can't map command '%s'", canon)
        }

        fp(args[1:])
        
}
