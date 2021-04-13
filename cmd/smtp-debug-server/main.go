package main

import (
	"flag"
	"io"
	"log"
	"os"

	"github.com/linanh/go-smtp"
	"go.uber.org/zap"
)

var addr = "127.0.0.1:1025"

func init() {
	flag.StringVar(&addr, "l", addr, "Listen address")
}

type backend struct{}

func (bkd *backend) Login(state *smtp.ConnectionState, username, password, sid string) (smtp.Session, error) {
	return &session{}, nil
}

func (bkd *backend) AnonymousLogin(state *smtp.ConnectionState, sid string) (smtp.Session, error) {
	return &session{}, nil
}

func (bkd *backend) GenerateSID() string {
	return ""
}

type session struct{}

func (s *session) Mail(from string, opts smtp.MailOptions) error {
	return nil
}

func (s *session) Rcpt(to string, opts smtp.RcptOptions) error {
	return nil
}

func (s *session) Data(r io.Reader) error {
	return nil
}

func (s *session) Reset() {}

func (s *session) Logout() error {
	return nil
}

func main() {
	flag.Parse()

	logger, _ := zap.NewProduction()
	defer logger.Sync()
	sugar := logger.Sugar()

	s := smtp.NewServer(&backend{}, sugar)

	s.Addr = addr
	s.Domain = "localhost"
	s.AllowInsecureAuth = true
	s.Debug = os.Stdout

	log.Println("Starting SMTP server at", addr)
	log.Fatal(s.ListenAndServe())
}
