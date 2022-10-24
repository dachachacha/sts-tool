package main

import (
        "io/ioutil"
        "log"
        "path/filepath"
        "reflect"

        "github.com/hashicorp/go-memdb"
)

func loadData(folderPath string, tableName string, factory ConfigObjFactory) {
    txn := db.Txn(true)
    items, _ := ioutil.ReadDir(folderPath)
    for _, item := range items {
        file := filepath.Join(folderPath,item.Name())
        log.Printf("loading data file: %s",file)
        obj := factory()
        log.Printf("%v",reflect.TypeOf(obj))
        readObject(file,obj)
        log.Printf("%v",obj)
        if err := txn.Insert(tableName,obj); err != nil {
            panic(err)
        }
    }
    txn.Commit()
    txn = db.Txn(false)
    defer txn.Abort()
    it, err := txn.Get(tableName, "id")
    if err != nil {
        panic(err)
    }
    log.Printf("All the %ss:\n",tableName)
    for obj := it.Next(); obj != nil; obj = it.Next() {
        i := reflect.ValueOf(obj)
        log.Printf("  %v\n", reflect.Indirect(i).FieldByName("Urn"))
        if tableName == "client" {
            log.Printf("  %v\n", reflect.Indirect(i).FieldByName("AllowedAudiences"))
            log.Printf("  %v\n", reflect.Indirect(i).FieldByName("AllowedStsRequests"))
        }
    }
}

func GetIssuerFromDB(urn string) (*Issuer, error) {
    configObjRaw, err := GetConfigObj("issuer", urn)
    issuer := reflect.ValueOf(configObjRaw).Interface().(*Issuer)
    return issuer, err
}
func GetValidatorFromDB(urn string) (*Validator, error) {
    configObjRaw, err := GetConfigObj("validator", urn)
    validator := reflect.ValueOf(configObjRaw).Interface().(*Validator)
    return validator, err
}
func GetRequestedTokenTypeFromDB(urn string) (*RequestedTokenType, error) {
    configObjRaw, err := GetConfigObj("requested_token_type", urn)
    requestedTokenType := reflect.ValueOf(configObjRaw).Interface().(*RequestedTokenType)
    return requestedTokenType, err
}
func GetAuthenticatorFromDB(urn string) (*Authenticator, error) {
    configObjRaw, err := GetConfigObj("authenticator", urn)
    authenticator := reflect.ValueOf(configObjRaw).Interface().(*Authenticator)
    return authenticator, err
}
func GetClientFromDB(urn string) (*Client, error) {
    configObjRaw, err := GetConfigObj("client", urn)
    client := reflect.ValueOf(configObjRaw).Interface().(*Client)
    return client, err
}

func GetConfigObj(tableName string, urn string) (interface{},error) {
    txn := db.Txn(false)
    defer txn.Abort()
    raw, err := txn.First(tableName, "id", urn)
    if err != nil {
        return nil, err
    }
    configObj := raw
    return configObj, nil
}

func CreateDB (tables []string) *memdb.MemDB {
    schema := &memdb.DBSchema{
        Tables: make(map[string]*memdb.TableSchema),
    }
    for _, v := range tables {
        log.Printf("adding table:%v", v)
        schema.Tables[v] = &memdb.TableSchema{
                Name: v,
                Indexes: map[string]*memdb.IndexSchema{
                    "id": &memdb.IndexSchema{
                        Name:    "id",
                        Unique:  true,
                        Indexer: &memdb.StringFieldIndex{Field: "Urn"},
                    },
                },
        }
    } 
    var err error
    db, err = memdb.NewMemDB(schema)
    if err != nil {
        panic(err)
    }
    log.Printf("DB:%v",db)
    return db
}
