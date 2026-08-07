package routes

import (
	"fmt"
	"net/http"
	"time"

	"github.com/devlup-labs/Ghostwire/coordination-server/database" // Import database package
	"github.com/devlup-labs/Ghostwire/coordination-server/routes/general"
	"github.com/gorilla/mux"
)

// 1. Accept store interface as a parameter
func CreateServer(store database.Store) (srv *http.Server) {
	srv = &http.Server{
		Handler:      createRouter(store), // Pass store to router
		Addr:         "127.0.0.1:8000",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	return
}

func createRouter(store database.Store) (router *mux.Router) {
	router = mux.NewRouter()

	// 2. Pass store to handlers (we will update register/checkin to accept this)
	v1subrouter := router.PathPrefix("/api/v1").Subrouter()
	v1subrouter.HandleFunc("/connect", general.ConnectHandler)
	v1subrouter.HandleFunc("/checkin", general.MakeCheckinHandler(store))
	v1subrouter.HandleFunc("/register", general.MakeRegisterHandler(store))

	router.HandleFunc("/api", versionCheckHandler)
	router.HandleFunc("/", rootHandler)

	return
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func versionCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "ghostwire v%s API v%s", "0.0.0", "1")
}
