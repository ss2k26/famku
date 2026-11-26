// Package mailer sends the two transactional mails (verify e-mail, reset password).
package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// ---- templates ---------------------------------------------------------------------------------

func verifyText(app, name, link string) (string, string) {
	return "Confirm your email address for " + app,
		fmt.Sprintf("Hi %s,\n\nConfirm your email address to finish setting up your %s account:\n\n%s\n\nThe link is valid for 24 hours and works once. If you did not create this account you can ignore this message.\n", name, app, link)
}

func resetText(app, name, link string) (string, string) {
	return "Reset your " + app + " password",
		fmt.Sprintf("Hi %s,\n\nSomeone asked to reset the password of your %s account. To choose a new password open:\n\n%s\n\nThe link is valid for 30 minutes and works once. If you did not ask for this, ignore this message: your password stays as it is.\n", name, app, link)
}

// ---- development: print the mail instead of sending it -----------------------------------------

type Log struct {
	App    string
	Logger *slog.Logger
}

func (l Log) SendPasswordReset(_ context.Context, to, name, link string) error {
	subj, body := resetText(l.App, name, link)
	l.Logger.Info("mail (not sent, MAIL_DRIVER=log)", "to", to, "subject", subj, "body", body)
	return nil
}

func (l Log) SendVerifyEmail(_ context.Context, to, name, link string) error {
	subj, body := verifyText(l.App, name, link)
	l.Logger.Info("mail (not sent, MAIL_DRIVER=log)", "to", to, "subject", subj, "body", body)
	return nil
}

// ---- SMTP --------------------------------------------------------------------------------------

type SMTP struct {
	App      string
	Host     string
	Port     int
	User     string
	Password string
	From     string // "Famku <no-reply@example.com>"
	TLS      string // starttls (587) | tls (465) | none (local relay / MailHog only)
	Logger   *slog.Logger
}

func (s *SMTP) SendPasswordReset(ctx context.Context, to, name, link string) error {
	subj, body := resetText(s.App, name, link)
	return s.log(s.send(ctx, to, subj, body), to)
}

func (s *SMTP) SendVerifyEmail(ctx context.Context, to, name, link string) error {
	subj, body := verifyText(s.App, name, link)
	return s.log(s.send(ctx, to, subj, body), to)
}

func (s *SMTP) log(err error, to string) error {
	if err != nil && s.Logger != nil {
		s.Logger.Error("smtp send failed", "err", err, "to", to)
	}
	return err
}

func (s *SMTP) send(ctx context.Context, to, subject, body string) error {
	from, err := mail.ParseAddress(s.From)
	if err != nil {
		return fmt.Errorf("bad SMTP_FROM: %w", err)
	}
	rcpt, err := mail.ParseAddress(to)
	if err != nil || strings.ContainsAny(to+subject, "\r\n") { // header injection guard
		return errors.New("invalid recipient or subject")
	}
	addr := net.JoinHostPort(s.Host, fmt.Sprint(s.Port))
	d := net.Dialer{Timeout: 10 * time.Second}
	cfg := &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}
	var conn net.Conn
	if s.TLS == "tls" {
		conn, err = (&tls.Dialer{NetDialer: &d, Config: cfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		return err
	}
	defer c.Close()
	if s.TLS == "starttls" {
		if err := c.StartTLS(cfg); err != nil {
			return err
		}
	}
	if s.User != "" {
		if err := c.Auth(smtp.PlainAuth("", s.User, s.Password, s.Host)); err != nil { // refuses to send the password in clear text
			return err
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(rcpt.Address); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	var sb strings.Builder
	h := func(k, v string) { sb.WriteString(k + ": " + v + "\r\n") }
	h("From", from.String())
	h("To", rcpt.String())
	h("Subject", mime.QEncoding.Encode("utf-8", subject))
	h("Date", time.Now().Format(time.RFC1123Z))
	h("Message-ID", fmt.Sprintf("<%d.%s@%s>", time.Now().UnixNano(), "famku", s.Host))
	h("MIME-Version", "1.0")
	h("Content-Type", `text/plain; charset="utf-8"`)
	h("Content-Transfer-Encoding", "quoted-printable")
	h("Auto-Submitted", "auto-generated")
	sb.WriteString("\r\n")
	if _, err := w.Write([]byte(sb.String())); err != nil {
		return err
	}
	qp := quotedprintable.NewWriter(w)
	if _, err := qp.Write([]byte(strings.ReplaceAll(body, "\n", "\r\n"))); err != nil {
		return err
	}
	if err := qp.Close(); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
