package main

import (
        "crypto/ecdsa"
        "crypto/x509"
        "encoding/pem"
        "strings"

        "github.com/golang-jwt/jwt/v4"
)

func parseECPrivateKeyFromPEM(issuerKeyPEM string, alg string) *ecdsa.PrivateKey {
        var key *ecdsa.PrivateKey
        var err error
        if strings.HasPrefix(alg,"ES") {
                key, err = jwt.ParseECPrivateKeyFromPEM([]byte(issuerKeyPEM))
        } else if strings.HasPrefix(alg,"RS") {
                key, err = jwt.ParseECPrivateKeyFromPEM([]byte(issuerKeyPEM))
        }
        if err != nil {
                die("Unable to parse private key: %v\n", err)
        }
        return key
}

func parseECPublicKeyFromCertPEM(validatorKeyPEM string, alg string) *ecdsa.PublicKey {
        var key *ecdsa.PublicKey
        var pubKey any
        var err error
        if strings.HasPrefix(alg,"ES") {
                block, _ := pem.Decode([]byte(validatorKeyPEM))
                cert, err := x509.ParseCertificate(block.Bytes)
                if  err != nil {
                    die("failed to parse Cert PEM block containing the public key")
                }
                pubKey = cert.PublicKey
                if err != nil {
                    die("couldn't convert x509 PEM to Public Key")
                }
                key = pubKey.(*ecdsa.PublicKey)
                //key, err = jwt.ParseECPublicKeyFromPEM([]byte(validatorKeyPEM))
        } else {
            die("Algo not supported")
        }
        if err != nil {
                die("Unable to parse public key: %v\n", err)
        }
        return key
}
