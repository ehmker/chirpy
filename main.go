package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)



func main(){

const port = "8080"
database, err := NewDB("database.json")
godotenv.Load()

if err != nil{
	log.Fatal("unable to connect to database")
}


config := &apiConfig{
	fileserverHits: 0,
	nextID: 0,
	db: *database,
	jwtSecret: os.Getenv("JWT_SECRET"),
	polkaAPIKey: os.Getenv("POLKA_API_KEY"),

}

mux := http.NewServeMux()
mux = attachHandlers(mux, config)

srv := &http.Server{
	Addr: ":" + port,
	Handler: mux,
}

log.Printf("Serving on %s\n", port)
log.Fatal(srv.ListenAndServe())
}

