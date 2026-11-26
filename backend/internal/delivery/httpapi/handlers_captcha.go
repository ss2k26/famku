package httpapi

import "net/http"

// captchaConfig tells the frontend which widget to show and when a captcha is demanded.
func (s *Server) captchaConfig(w http.ResponseWriter, r *http.Request) {
	info := s.Captcha.Info()
	writeJSON(w, http.StatusOK, map[string]any{
		"provider": info.Provider,
		"siteKey":  info.SiteKey,
		"mode":     s.Cfg.CaptchaMode, // off | adaptive | always (login); register/reset always use it unless off
	})
}

// captchaChallenge issues a proof-of-work challenge (provider "pow" only).
func (s *Server) captchaChallenge(w http.ResponseWriter, r *http.Request) {
	ch, err := s.Captcha.NewChallenge()
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "not_found", "Not found.")
		return
	}
	writeJSON(w, http.StatusOK, ch)
}
