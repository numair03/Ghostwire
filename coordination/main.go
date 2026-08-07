package main

import (
	"log"

	"github.com/devlup-labs/Ghostwire/coordination-server/database" // 1. Added import
	"github.com/devlup-labs/Ghostwire/coordination-server/routes"
)

func main() {
	store := database.NewFakeStore() // 2. Instantiate Fake Store

	srv := routes.CreateServer(store) // 3. Pass store here
	log.Fatal(srv.ListenAndServe())
}
