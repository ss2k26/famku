package httpapi

import (
	"net/http"
	"time"

	"famku/internal/domain"
	"famku/internal/usecase"
)

type userDTO struct {
	ID               string    `json:"id"`
	Email            string    `json:"email"`
	Username         string    `json:"username"`
	Name             string    `json:"name"`
	EmailVerified    bool      `json:"emailVerified"`
	TwoFactorEnabled bool      `json:"twoFactorEnabled"`
	CreatedAt        time.Time `json:"createdAt"`
}

func toUserDTO(u *domain.User) userDTO {
	return userDTO{ID: u.ID, Email: u.Email, Username: u.Username, Name: u.Name, EmailVerified: u.EmailVerified(), TwoFactorEnabled: u.TOTPEnabled, CreatedAt: u.CreatedAt}
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name, Username, Email, Password string
		Captcha                         string `json:"captcha"`
	}
	if !decode(w, r, &in) {
		return
	}
	_, err := s.Auth.Register(r.Context(), usecase.RegisterInput{Name: in.Name, Username: in.Username, Email: in.Email, Password: in.Password, CaptchaToken: in.Captcha, Meta: meta(r)})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// same answer whether or not the address already existed (when e-mail verification is required)
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "ok", "verificationRequired": s.Cfg.RequireVerifiedEmail})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Identifier   string `json:"identifier"` // email or username
		Email        string `json:"email"`      // older clients: same meaning as identifier
		Password     string
		Captcha      string `json:"captcha"`
		TOTPCode     string `json:"totpCode"`
		RecoveryCode string `json:"recoveryCode"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Password) > usecase.MaxPasswordLen*4 { // do not feed huge inputs to the hasher
		s.fail(w, r, domain.ErrInvalidCredentials)
		return
	}
	res, err := s.Auth.Login(r.Context(), usecase.LoginInput{Identifier: firstNonEmpty(in.Identifier, in.Email), Password: in.Password, CaptchaToken: in.Captcha,
		TOTPCode: in.TOTPCode, RecoveryCode: in.RecoveryCode, Meta: meta(r)})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.setCookie(w, res.Token, res.Session.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]any{"user": toUserDTO(res.User), "csrfToken": res.Session.CSRFToken})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	a := authOf(r.Context())
	if err := s.Auth.Logout(r.Context(), a.sess, meta(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	s.clearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	a := authOf(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"user": toUserDTO(a.user), "csrfToken": a.sess.CSRFToken})
}

func (s *Server) forgotPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email   string
		Captcha string `json:"captcha"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := s.Auth.RequestPasswordReset(r.Context(), in.Email, in.Captcha, meta(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "ok"}) // identical for known and unknown addresses
}

func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request) {
	var in struct{ Token, Password string }
	if !decode(w, r, &in) {
		return
	}
	if err := s.Auth.ResetPassword(r.Context(), in.Token, in.Password, meta(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) verifyEmail(w http.ResponseWriter, r *http.Request) {
	var in struct{ Token string }
	if !decode(w, r, &in) {
		return
	}
	if err := s.Auth.VerifyEmail(r.Context(), in.Token, meta(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) resendVerification(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email   string
		Captcha string `json:"captcha"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := s.Auth.ResendVerification(r.Context(), in.Email, in.Captcha, meta(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "ok"})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
