package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	*sql.DB
}

type User struct {
	ID       int
	Username string
	FullName string
	Email    string
	Org      string
	Bio      string
}

type Proposal struct {
	ID        int
	UserID    int
	Speaker   string
	Title     string
	Abstract  string
	Track     string
	Status    string
	CreatedAt string
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	username      TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	full_name     TEXT NOT NULL DEFAULT '',
	email         TEXT NOT NULL DEFAULT '',
	org           TEXT NOT NULL DEFAULT '',
	bio           TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS proposals (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id    INTEGER NOT NULL REFERENCES users(id),
	title      TEXT NOT NULL,
	abstract   TEXT NOT NULL,
	track      TEXT NOT NULL,
	status     TEXT NOT NULL DEFAULT 'draft',
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);`

func OpenDB(path string) (*DB, error) {
	conn, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(schema); err != nil {
		return nil, err
	}
	db := &DB{conn}
	if err := db.seed(); err != nil {
		return nil, err
	}
	return db, nil
}

// VULN-4 (weak password storage): passwords are hashed with plain MD5 and no
// salt. MD5 is fast, so leaked hashes can be cracked in seconds, and two users
// with the same password get the same hash.
func hashPassword(password string) string {
	sum := md5.Sum([]byte(password))
	return hex.EncodeToString(sum[:])
}

// seed adds two fake speakers and their proposals the first time the app runs,
// so there is something to look at (and someone else's data to "leak").
// All names, emails and passwords here are made up.
func (db *DB) seed() error {
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	speakers := []struct {
		username, password, name, email, org, bio string
	}{
		{"amara", "sunshine1", "Amara Obi", "amara@example.com", "Lagos Devs", "Backend engineer who loves Go and good coffee."},
		{"kofi", "password123", "Kofi Mensah", "kofi@example.com", "Accra Cloud Meetup", "Platform engineer, Kubernetes tinkerer."},
	}
	for _, s := range speakers {
		_, err := db.Exec(
			"INSERT INTO users (username, password_hash, full_name, email, org, bio) VALUES (?, ?, ?, ?, ?, ?)",
			s.username, hashPassword(s.password), s.name, s.email, s.org, s.bio,
		)
		if err != nil {
			return fmt.Errorf("seeding %s: %w", s.username, err)
		}
	}

	proposals := []struct {
		userID                 int
		title, abstract, track string
		status                 string
	}{
		{1, "Shipping Go Services Without Tears", "A practical walk through how our team ships small Go services.", "Engineering", "submitted"},
		{1, "UNPUBLISHED: My Big Keynote Idea", "Draft only. Please don't share this yet, I'm still working on it.", "Keynote", "draft"},
		{2, "Kubernetes on a Budget", "Running clusters for a community meetup with almost no money.", "Cloud Native", "submitted"},
	}
	for _, p := range proposals {
		_, err := db.Exec(
			"INSERT INTO proposals (user_id, title, abstract, track, status) VALUES (?, ?, ?, ?, ?)",
			p.userID, p.title, p.abstract, p.track, p.status,
		)
		if err != nil {
			return fmt.Errorf("seeding proposal: %w", err)
		}
	}
	return nil
}
