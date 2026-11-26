package httpapi

import (
	"net/http"
	"time"
)

func (s *Server) updateProfile(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name string }
	if !decode(w, r, &in) {
		return
	}
	u, err := s.Auth.UpdateProfile(r.Context(), authOf(r.Context()).user.ID, in.Name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": toUserDTO(u)})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if !decode(w, r, &in) {
		return
	}
	a := authOf(r.Context())
	if err := s.Auth.ChangePassword(r.Context(), a.user.ID, a.sess.ID, in.CurrentPassword, in.NewPassword, meta(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type sessionDTO struct {
	ID         string    `json:"id"`
	UserAgent  string    `json:"userAgent"`
	IP         string    `json:"ip"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	Current    bool      `json:"current"`
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	a := authOf(r.Context())
	list, err := s.Auth.ListSessions(r.Context(), a.user.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]sessionDTO, 0, len(list))
	for _, x := range list {
		out = append(out, sessionDTO{ID: x.ID, UserAgent: x.UserAgent, IP: x.IP, CreatedAt: x.CreatedAt, LastSeenAt: x.LastSeenAt, Current: x.ID == a.sess.ID})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	a := authOf(r.Context())
	id := r.PathValue("id")
	if id == a.sess.ID { // use logout for the current session
		writeAPIError(w, http.StatusBadRequest, "bad_request", "Use sign out for the current session.")
		return
	}
	if err := s.Auth.RevokeSession(r.Context(), a.user.ID, id, meta(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) revokeOthers(w http.ResponseWriter, r *http.Request) {
	a := authOf(r.Context())
	if err := s.Auth.LogoutOthers(r.Context(), a.user.ID, a.sess.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) twoFactorSetup(w http.ResponseWriter, r *http.Request) {
	st, err := s.Auth.BeginTwoFactor(r.Context(), authOf(r.Context()).user.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": st.Secret, "uri": st.URI})
}

func (s *Server) twoFactorEnable(w http.ResponseWriter, r *http.Request) {
	var in struct{ Code string }
	if !decode(w, r, &in) {
		return
	}
	codes, err := s.Auth.EnableTwoFactor(r.Context(), authOf(r.Context()).user.ID, in.Code, meta(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes})
}

func (s *Server) twoFactorDisable(w http.ResponseWriter, r *http.Request) {
	var in struct{ Password, Code string }
	if !decode(w, r, &in) {
		return
	}
	if err := s.Auth.DisableTwoFactor(r.Context(), authOf(r.Context()).user.ID, in.Password, in.Code, meta(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) recoveryCodes(w http.ResponseWriter, r *http.Request) {
	var in struct{ Password string }
	if !decode(w, r, &in) {
		return
	}
	codes, err := s.Auth.RegenerateRecoveryCodes(r.Context(), authOf(r.Context()).user.ID, in.Password)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes})
}
