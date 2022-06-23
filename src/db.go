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
    }
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
