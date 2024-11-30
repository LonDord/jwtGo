package initializers

import (
	"net/smtp"
	"os"
)

var SmtpAuth smtp.Auth

func ConnectToMail() {
	SmtpAuth = smtp.PlainAuth("", os.Getenv("FROM_EMAIL"), os.Getenv("FROM_PASSWORD"), os.Getenv("SMTP_HOST"))
}
