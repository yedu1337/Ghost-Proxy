package logger

import (
	"log/slog"
	"os"
)

var Logger = slog.New(
	slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}),
)

func SetLevel(level string) {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn", "warning":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

func Info(message string, args ...any) {
	Logger.Info(message, args...)
}

func Warn(message string, args ...any) {
	Logger.Warn(message, args...)
}

func Error(message string, args ...any) {
	Logger.Error(message, args...)
}
