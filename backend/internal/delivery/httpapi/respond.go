package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"famku/internal/domain"
)

type apiError struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]apiError{"error": {Code: code, Message: msg}})
}

// maxBody bounds every JSON request (the API only receives small documents).
const maxBody = 64 << 10

// decode reads exactly one JSON object, rejects unknown fields and oversized bodies.
func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeAPIError(w, http.StatusRequestEntityTooLarge, "too_large", "Request is too large.")
		} else {
			writeAPIError(w, http.StatusBadRequest, "bad_request", "The request body is not valid.")
		}
		return false
	}
	if _, err := dec.Token(); err != io.EOF { // trailing data
		writeAPIError(w, http.StatusBadRequest, "bad_request", "The request body is not valid.")
		return false
	}
	return true
}

// fail maps domain errors to responses. Messages are deliberately generic where detail would leak information.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ve *domain.ValidationError
	var le *domain.LockedError
	switch {
	case errors.As(err, &ve):
		writeJSON(w, 422, map[string]apiError{"error": {Code: "validation", Message: "Please check the highlighted fields.", Fields: ve.Fields}})
	case errors.As(err, &le):
		retry(w, le.RetryAfter)
		writeAPIError(w, 429, "account_locked", "Too many failed attempts. Try again later, or reset your password.")
	case errors.Is(err, domain.ErrInvalidCredentials):
		writeAPIError(w, 401, "invalid_credentials", "Email or password is incorrect.")
	case errors.Is(err, domain.ErrCaptchaRequired):
		writeAPIError(w, 403, "captcha_required", "Please complete the security check.")
	case errors.Is(err, domain.ErrCaptchaFailed):
		writeAPIError(w, 403, "captcha_failed", "The security check failed. Please try again.")
	case errors.Is(err, domain.ErrTwoFactorRequired):
		writeAPIError(w, 401, "two_factor_required", "Enter the code from your authenticator app.")
	case errors.Is(err, domain.ErrInvalidTwoFactor):
		writeAPIError(w, 401, "invalid_two_factor", "That code is not valid.")
	case errors.Is(err, domain.ErrEmailNotVerified):
		writeAPIError(w, 403, "email_not_verified", "Confirm your email address first. Check your inbox.")
	case errors.Is(err, domain.ErrRegistrationClosed):
		writeAPIError(w, 403, "registration_closed", "Registration is closed.")
	case errors.Is(err, domain.ErrConflict):
		writeAPIError(w, 409, "conflict", "This could not be completed. If you already have an account, sign in or reset your password.")
	case errors.Is(err, domain.ErrInvalidToken):
		writeAPIError(w, 400, "invalid_token", "This link is invalid or has expired. Request a new one.")
	case errors.Is(err, domain.ErrUnauthenticated):
		writeAPIError(w, 401, "unauthenticated", "Please sign in.")
	case errors.Is(err, domain.ErrNotFound):
		writeAPIError(w, 404, "not_found", "Not found.")
	default:
		s.Logger.Error("request failed", "err", err, "request_id", requestID(r.Context()), "path", r.URL.Path)
		writeAPIError(w, 500, "internal", "Something went wrong. Please try again.")
	}
}

func retry(w http.ResponseWriter, d time.Duration) {
	if d < time.Second {
		d = time.Second
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(d.Seconds()+0.999)))
}
