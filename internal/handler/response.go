package handler

import (
	"encoding/json"
	"net/http"
)

// APIError represents a structured error response.
type APIError struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code"`
}

// respondJSON writes a JSON response with the given status code.
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

// respondError writes a JSON error response.
func respondError(w http.ResponseWriter, status int, errMsg string) {
	respondJSON(w, status, APIError{
		Error:   http.StatusText(status),
		Message: errMsg,
		Code:    status,
	})
}
