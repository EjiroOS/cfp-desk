// cfp-desk is a small call-for-proposals app for community events.
//
// WARNING: this is the deliberately VULNERABLE version, built for learning.
// Run it on your own machine only (localhost). Never deploy it.
package main

import (
	"embed"
	"html/template"
	"log"
	"net/http"
	"os"
)

//go:embed templates/*.html
var templateFiles embed.FS

//go:embed static
var staticFiles embed.FS

type App struct {
	db        *DB
	templates map[string]*template.Template
	sessions  *SessionStore
}

func main() {
	dbPath := getenv("DB_PATH", "cfp-desk.db")
	port := getenv("PORT", "8080")

	db, err := OpenDB(dbPath)
	if err != nil {
		log.Fatalf("could not open database: %v", err)
	}
	defer db.Close()

	app := &App{
		db:        db,
		templates: loadTemplates(),
		sessions:  NewSessionStore(),
	}

	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.FileServerFS(staticFiles))

	mux.HandleFunc("GET /{$}", app.home)
	mux.HandleFunc("GET /login", app.loginPage)
	mux.HandleFunc("POST /login", app.login)
	mux.HandleFunc("GET /register", app.registerPage)
	mux.HandleFunc("POST /register", app.register)
	mux.HandleFunc("POST /logout", app.logout)

	mux.HandleFunc("GET /profile", app.requireLogin(app.profilePage))
	mux.HandleFunc("POST /profile", app.requireLogin(app.updateProfile))

	mux.HandleFunc("GET /proposals", app.requireLogin(app.listProposals))
	mux.HandleFunc("GET /proposals/new", app.requireLogin(app.newProposalPage))
	mux.HandleFunc("POST /proposals", app.requireLogin(app.createProposal))
	mux.HandleFunc("GET /proposals/{id}", app.requireLogin(app.showProposal))

	// Inside Docker the app listens on all interfaces, but docker-compose.yml
	// only publishes it on 127.0.0.1, so nothing outside your Mac can reach it.
	addr := ":" + port
	log.Printf("cfp-desk listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// loadTemplates parses each page together with the shared layout.
func loadTemplates() map[string]*template.Template {
	pages := []string{"login", "register", "profile", "proposals", "new_proposal", "proposal"}
	t := make(map[string]*template.Template)
	for _, p := range pages {
		t[p] = template.Must(template.ParseFS(templateFiles, "templates/layout.html", "templates/"+p+".html"))
	}
	return t
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
