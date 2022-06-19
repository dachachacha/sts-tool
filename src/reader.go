package main

import (
        "io/ioutil"
        "log"

        "gopkg.in/yaml.v3"
)


func readYml(ymlFileName string) ([]byte, error) {
        ymlFile, err := ioutil.ReadFile(ymlFileName)
        return ymlFile, err
}

func readIssuer(ymlFileName string, issuer *Issuer) error {
        ymlFile, err := readYml(ymlFileName)
        if err != nil {
                log.Fatalf("file read: %s, err:   #%v ", ymlFileName, err)
        }
        err = yaml.Unmarshal(ymlFile, &issuer)
        if err != nil {
                log.Fatalf("load issuer err:   #%v ", err)
        }
        return err
}
func readValidator(ymlFileName string, validator *Validator) error {
        ymlFile, err := readYml(ymlFileName)
        if err != nil {
                log.Fatalf("file read: %s, err:   #%v ", ymlFileName, err)
        }
        err = yaml.Unmarshal(ymlFile, &validator)
        if err != nil {
                log.Fatalf("load validator err:   #%v ", err)
        }
        return err
}
func readRequestedTokenType(ymlFileName string, rtt *RequestedTokenType) error {
        ymlFile, err := readYml(ymlFileName)
        if err != nil {
                log.Fatalf("file read: %s, err:   #%v ", ymlFileName, err)
        }
        err = yaml.Unmarshal(ymlFile, &rtt)
        if err != nil {
                log.Fatalf("load requested_token_type err:   #%v ", err)
        }
        return err
}
func readSubjectTokenType(ymlFileName string, stt *SubjectTokenType) error {
        ymlFile, err := readYml(ymlFileName)
        if err != nil {
                log.Fatalf("file read: %s, err:   #%v ", ymlFileName, err)
        }
        err = yaml.Unmarshal(ymlFile, &stt)
        if err != nil {
                log.Fatalf("load requested_token_type err:   #%v ", err)
        }
        return err
}
