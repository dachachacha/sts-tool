package main

import (
)

type Config struct {
    Authenticators string
    Clients string
    Issuers string
    RequestedTokenTypes string
    SubjectTokenTypes string
    Validators string
}

type ConfigObj interface {
    GetUrn() string
}
type ConfigObjFactory func() ConfigObj 

type Authenticator struct {
        Urn string `yaml:"urn"`
        Cert string `yaml:"cert"`
        Alg string `yaml:"alg"`
        Issuer string `yaml:"issuer"`
}
func (a Authenticator) GetUrn() string {
    return a.Urn
}
func CreateAuthenticator() ConfigObj {
    return new(Authenticator)
}
type AllowedStsRequest struct {
    SubjectTokenType string `yaml:"subject_token_type"`
    RequestedTokenType string `yaml:"requested_token_type"`
}
type Client struct {
        Urn string `yaml:"urn"`
        AllowedAudiences []string `yaml:"allowed_audiences"`
        AllowedStsRequests []AllowedStsRequest `yaml:"allowed_sts_requests"`
}
func (c Client) GetUrn() string {
    return c.Urn
}
func CreateClient() ConfigObj {
    return new(Client)
}
type Issuer struct {
        Urn string `yaml:"urn"`
        Key string `yaml:"key"`
        Lifetime int `yaml:"lifetime"`
        Cert string `yaml:"cert"`
        Alg string `yaml:"alg"`
}
func (i Issuer) GetUrn() string {
    return i.Urn
}
func CreateIssuer() ConfigObj {
    return new(Issuer)
}
type Validator struct {
        Urn string `yaml:"urn"`
        Cert string `yaml:"cert"`
        Alg string `yaml:"alg"`
        Issuer string `yaml:"issuer"`
}
func (v Validator) GetUrn() string {
    return v.Urn
}
func CreateValidator() ConfigObj {
    return new(Validator)
}
type RequestedTokenType struct {
        Urn string `yaml:"urn"`
        Audience string `yaml:"audience"`
        Issuer string `yaml:"issuer"`
        Claims []string `yaml:"claims"`
}
func (r RequestedTokenType) GetUrn() string {
    return r.Urn
}
func CreateRequestedTokenType() ConfigObj {
    return new(RequestedTokenType)
}
type SubjectTokenType struct {
        Urn string `yaml:"urn"`
        Audience string `yaml:"audience"`
        Validator string `yaml:"validator"`
        Issuer string `yaml:"issuer"`
}
func (s SubjectTokenType) GetUrn() string {
    return s.Urn
}
func CreateSubjectTokenType() ConfigObj {
    return new(SubjectTokenType)
}
