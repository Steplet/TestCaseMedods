package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	db, err := InitDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	err = createTable(db)
	if err != nil {
		log.Fatal(err)
	}

	err = RunServer(db)
	if err != nil {
		log.Fatal(err)
	}

}

func RunServer(db *sql.DB) error {
	log.Println("Starting server...")

	mux := http.NewServeMux()

	mux.HandleFunc("/", GUIDHandler(db))
	mux.HandleFunc("/info", infoHandler(db))
	mux.HandleFunc("/refresh", refreshHandler(db))
	mux.HandleFunc("/logout", logoutHandler(db))

	handler := withCORS(mux)

	err := http.ListenAndServe(":8080", handler)
	if err != nil {
		return fmt.Errorf("error starting server: %w", err)
	}

	return nil
}

func GUIDHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		GUID := r.URL.Query().Get("guid")
		if GUID == "" {
			http.Error(w, "Missing GUID", http.StatusBadRequest)
			return
		}
		userAgent := r.Header.Get("User-Agent")
		host := r.RemoteAddr

		exist, err := findGUID(db, GUID)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error finding GUID: %v", err), http.StatusBadRequest)
			return
		}
		if exist {
			tokens, err := UpdateTokens(db, GUID, userAgent, host)
			if err != nil {
				http.Error(w, fmt.Sprintf("Error updating tokens: %v", err), http.StatusInternalServerError)
				return
			}
			err = json.NewEncoder(w).Encode(tokens)
			if err != nil {
				http.Error(w, fmt.Sprintf("Error encoding tokens: %v", err), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		tokens, err := GenerateTokens(db, GUID, userAgent, host)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error generating tokens: %v", err), http.StatusInternalServerError)
			return
		}
		err = json.NewEncoder(w).Encode(tokens)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokens struct {
	ID                 int
	UserID             uuid.UUID
	HashedRefreshToken []byte
	ExpiresAt          time.Time
}

func infoHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var tokens Tokens

		err := json.NewDecoder(r.Body).Decode(&tokens)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("Got tokens: %v ", tokens)

		GUID, err := validateJWT(tokens.AccessToken)
		log.Printf("Parsing token issuer: %s", GUID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		exist, err := isFindValidRefreshToken(db, tokens.RefreshToken, GUID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !exist {
			http.Error(w, "Refresh token not found", http.StatusNotFound)
			return
		}

		w.Write([]byte(fmt.Sprintf("Tokens correct. Your GUID is %s ", GUID)))
		w.WriteHeader(http.StatusOK)

	}
}

func refreshHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var tokens Tokens

		err := json.NewDecoder(r.Body).Decode(&tokens)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userAgent := r.Header.Get("User-Agent")
		host := r.RemoteAddr

		log.Printf("Got tokens for refresh: %v", tokens)

		GUID, err := validateJWT(tokens.AccessToken)
		log.Printf("Parsing token issuer: %s", GUID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		exist, err := isFindValidRefreshToken(db, tokens.RefreshToken, GUID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !exist {
			http.Error(w, "Refresh token not found", http.StatusNotFound)
			return
		}
		exist, err = isFindUserAgentByRefreshToken(db, GUID, userAgent)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if !exist {
			w.Write([]byte("invalid user-agent starting logout\n"))
			err = Logout(db, tokens)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		}
		exist, err = IsFindRemoteAddr(db, GUID, host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !exist {
			w.Write([]byte("Send data to webhook, new ip adder\n"))
			payload := map[string]interface{}{
				"guid":      GUID,
				"new_ip":    host,
				"timestamp": time.Now(),
			}
			data, err := json.Marshal(payload)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			log.Printf("Sending data to webhook %s: %s", os.Getenv("WEBHOOK"), data)
			resp, err := http.Post(os.Getenv("WEBHOOK"), "application/json", bytes.NewBuffer(data))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer resp.Body.Close()
			log.Printf("webhook status: %v", resp.Status)
		}

		updatedTokens, err := UpdateTokens(db, GUID, userAgent, host)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error updating tokens: %v", err), http.StatusInternalServerError)
			return
		}
		w.Write([]byte("Tokens was refreshed\n"))
		err = json.NewEncoder(w).Encode(updatedTokens)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error encoding tokens: %v", err), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)

	}
}

func logoutHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var tokens Tokens

		err := json.NewDecoder(r.Body).Decode(&tokens)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("Got tokens for logout: %v", tokens)
		err = Logout(db, tokens)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error logout: %v", err), http.StatusInternalServerError)
			return
		}

		w.Write([]byte("Logout"))
		w.WriteHeader(http.StatusOK)
	}
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		log.Println("got cors request")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func Logout(db *sql.DB, tokens Tokens) error {
	GUID, err := validateJWT(tokens.AccessToken)
	log.Printf("Parsing token issuer: %s", GUID)
	if err != nil {
		return fmt.Errorf("Error validating JWT: %w", err)
	}
	exist, err := isFindValidRefreshToken(db, tokens.RefreshToken, GUID)
	if err != nil {
		return fmt.Errorf("Error find refresh token: %w", err)
	}
	if !exist {
		return fmt.Errorf("Refresh token not found")
	}

	err = deleteRefreshToken(db, GUID)
	if err != nil {
		return fmt.Errorf("Error deleting refresh token: %w", err)
	}
	return nil
}

func GenerateTokens(db *sql.DB, GUID, userAgent, host string) (*Tokens, error) {
	log.Printf("GUID %s does not exist", GUID)
	err := saveGUID(db, GUID)
	if err != nil {
		return nil, fmt.Errorf("error saving GUID: %w", err)
	}
	token, err := createJWTToken(GUID)
	if err != nil {
		return nil, fmt.Errorf("error creating JWT token: %w", err)
	}
	refreshToken, err := createRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("error creating refresh token: %w", err)
	}

	err = saveRefreshToken(db, refreshToken, GUID, userAgent, host)
	if err != nil {
		return nil, fmt.Errorf("error save refresh token: %w", err)
	}

	tokens := Tokens{AccessToken: token, RefreshToken: refreshToken}

	return &tokens, nil
}
func UpdateTokens(db *sql.DB, GUID, userAgent, host string) (*Tokens, error) {
	accessToken, err := createJWTToken(GUID)
	if err != nil {
		return nil, fmt.Errorf("error creating JWT token: %w", err)
	}
	refreshToken, err := createRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("error creating refresh token: %w", err)
	}
	exist, err := findRefreshToken(db, GUID)
	if err != nil {
		return nil, fmt.Errorf("error finding refresh token: %w", err)
	}
	if exist {
		err = deleteRefreshToken(db, GUID)
		if err != nil {
			return nil, fmt.Errorf("error deleting refresh token: %w", err)
		}
	}

	err = updateRefreshToken(db, refreshToken, GUID, userAgent, host)
	if err != nil {
		return nil, fmt.Errorf("error updating refresh token: %w", err)
	}
	tokens := Tokens{AccessToken: accessToken, RefreshToken: refreshToken}

	return &tokens, nil
}

func createJWTToken(guid string) (string, error) {
	claims := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.StandardClaims{
		Issuer:    guid,
		ExpiresAt: time.Now().Add(time.Minute * 20).Unix()})

	token, err := claims.SignedString([]byte(os.Getenv("SECRET_KEY")))
	if err != nil {
		return "", fmt.Errorf("error creating token: %w", err)
	}
	return token, nil
}

func createRefreshToken() (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", fmt.Errorf("error creating refresh token: %w", err)
	}
	return base64.StdEncoding.EncodeToString(token), nil
}

func validateJWT(token string) (string, error) {
	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("SECRET_KEY")), nil
	})
	if err != nil {
		return "", fmt.Errorf("error parsing JWT token: %w", err)
	}

	if claims, ok := t.Claims.(jwt.MapClaims); ok && t.Valid {
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			return "", fmt.Errorf("JWT token is expired")
		}
		if val, ok := claims["iss"]; ok {
			GUID, ok := val.(string)
			if !ok {
				return "", fmt.Errorf("GUID in token invalid")
			}
			return GUID, nil
		}
		return "", fmt.Errorf("invalid issuer in JWT token")
	}

	return "", fmt.Errorf("JWT token is invalid")
}

func InitDB() (*sql.DB, error) {
	connectionString := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST_CONTAINER"), os.Getenv("DB_PORT"), os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"))

	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, fmt.Errorf("error connecting to database: %w", err)
	}
	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf("error pinging database: %w", err)
	}

	log.Println("Successfully connected to database")

	return db, nil
}

func saveGUID(db *sql.DB, GUID string) error {
	log.Println("Saving GUID:", GUID)
	_, err := db.Exec("INSERT INTO users (id) VALUES ($1)", GUID)
	if err != nil {
		return fmt.Errorf("error saving GUID: %w", err)
	}
	log.Println("Successfully saved GUID:", GUID)

	return nil
}

func findGUID(db *sql.DB, GUID string) (bool, error) {
	log.Println("Finding GUID:", GUID)
	var exist bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)", GUID).Scan(&exist)
	if err != nil {
		return false, fmt.Errorf("error Scan GUID in Database: %w", err)
	}

	return exist, nil
}

func saveRefreshToken(db *sql.DB, refreshToken, guid, userAgent, host string) error {
	log.Println("Saving refresh token:", refreshToken)
	hashedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("error hashing refresh token: %w", err)
	}
	expiry := time.Now().Add(time.Hour * 2)
	log.Println("Exp time:", expiry)

	_, err = db.Exec(
		`INSERT INTO refresh_token (user_id, refresh_token, user_agent, remote_addr ,expires_at) VALUES ($1, $2, $3, $4, $5)
`, guid, hashedRefreshToken, userAgent, host, expiry)
	if err != nil {
		return fmt.Errorf("error saving refresh token: %w", err)
	}
	log.Println("Successfully saved refresh token:", refreshToken)

	return nil
}

func findRefreshToken(db *sql.DB, guid string) (bool, error) {
	log.Println("Finding refresh token for guid:", guid)
	var exist bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM refresh_token WHERE user_id = $1)", guid).Scan(&exist)
	if err != nil {
		return false, fmt.Errorf("error Scan exist in Database: %w", err)
	}

	return exist, nil
}

func updateRefreshToken(db *sql.DB, refreshToken, guid, userAgent, host string) error {
	log.Println("Updating refresh token:", refreshToken)

	hashedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("error hashing refresh token: %w", err)
	}
	expiry := time.Now().Add(time.Hour * 2)
	_, err = db.Exec(
		`INSERT INTO refresh_token (user_id, refresh_token, user_agent, remote_addr ,expires_at) VALUES ($1, $2, $3, $4, $5)
`, guid, hashedRefreshToken, userAgent, host, expiry)
	if err != nil {
		return fmt.Errorf("error update refresh token: %w", err)
	}
	log.Println("Successfully updated refresh token:", refreshToken)

	return nil
}

func IsFindRemoteAddr(db *sql.DB, guid, host string) (bool, error) {
	rows, err := db.Query("SELECT remote_addr  FROM refresh_token WHERE user_id = $1", guid)
	if err != nil {
		return false, fmt.Errorf("error querying refresh token: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var remoteAddr string
		if err := rows.Scan(&remoteAddr); err != nil {
			return false, fmt.Errorf("error scanning row: %w", err)
		}
		if remoteAddr == host {
			return true, nil
		}
	}

	return false, nil
}

func isFindUserAgentByRefreshToken(db *sql.DB, guid, userAgent string) (bool, error) {
	log.Println("Finding user agent by refresh token:", guid)

	rows, err := db.Query("SELECT user_agent  FROM refresh_token WHERE user_id = $1", guid)
	if err != nil {
		return false, fmt.Errorf("error querying refresh token: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var userAgentDB string
		if err = rows.Scan(&userAgentDB); err != nil {
			return false, fmt.Errorf("error scanning row: %w", err)
		}
		log.Printf("Found user agent: %s, but got %S", userAgentDB, userAgent)
		if userAgentDB == userAgent {
			return true, nil
		}
	}
	return false, nil
}

func isFindValidRefreshToken(db *sql.DB, refreshToken, guid string) (bool, error) {
	log.Println("Finding refresh token:", refreshToken)

	rows, err := db.Query("SELECT refresh_token, user_agent ,expires_at  FROM refresh_token WHERE user_id = $1", guid)
	if err != nil {
		return false, fmt.Errorf("error querying refresh token: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var refresh []byte
		var userAgentBD string
		var expTime time.Time

		if err := rows.Scan(&refresh, &userAgentBD, &expTime); err != nil {
			return false, fmt.Errorf("error scanning refresh token: %w", err)
		}
		err = bcrypt.CompareHashAndPassword([]byte(refresh), []byte(refreshToken))
		log.Println("exp time after ", expTime, time.Now())
		if err == nil && expTime.After(time.Now()) {
			return true, nil
		}

	}
	return false, fmt.Errorf("error finding refresh token: invalid refresh token or expiered")
}

func deleteRefreshToken(db *sql.DB, guid string) error {
	log.Println("Deleting refresh token for guid:", guid)
	_, err := db.Exec("DELETE FROM refresh_token WHERE user_id = $1", guid)
	if err != nil {
		return fmt.Errorf("error deleting refresh token: %w", err)
	}
	log.Println("Successfully deleted refresh token for guid:", guid)

	return nil
}

func createTable(db *sql.DB) error {
	log.Println("Creating table...")
	query := `
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP  
);

CREATE TABLE IF NOT EXISTS refresh_token (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    refresh_token TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    remote_addr TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`
	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("error creating users table: %w", err)
	}

	log.Println("End creating table")

	return nil
}
