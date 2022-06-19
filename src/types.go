package main

import (
)

type Issuer struct {
        Urn string `yaml:"urn"`
        Key string `yaml:"key"`
        Alg string `yaml:"alg"`
}
type Validator struct {
        Urn string `yaml:"urn"`
        Cert string `yaml:"cert"`
        Alg string `yaml:"alg"`
        Issuer string `yaml:"issuer"`
}
type RequestedTokenType struct {
        Urn string `yaml:"urn"`
        Audience string `yaml:"audience"`
        Issuer string `yaml:"issuer"`
}
type SubjectTokenType struct {
        Urn string `yaml:"urn"`
        Audience string `yaml:"audience"`
        Validator string `yaml:"validator"`
        Issuer string `yaml:"issuer"`
}
