package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sentinel-adaptive/internal/analytics"
	"sentinel-adaptive/internal/bot"
	"sentinel-adaptive/internal/config"
	"sentinel-adaptive/internal/modules/audit"
	"sentinel-adaptive/internal/playbook"
	"sentinel-adaptive/internal/risk"
	"sentinel-adaptive/internal/storage"
	"sentinel-adaptive/internal/trust"

	"go.uber.org/zap"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}

	logger, err := config.BuildLogger(cfg.LogLevel)
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = logger.Sync()
	}()

	store, err := storage.New(cfg.DatabasePath)
	if err != nil {
		logger.Fatal("storage init failed", zap.Error(err))
	}
	defer store.Close()
	if err := store.Migrate(); err != nil {
		logger.Fatal("migrations failed", zap.Error(err))
	}

	auditLogger := audit.NewLogger(store, logger)
	trustEngine := trust.NewEngine(cfg.Trust)
	riskEngine := risk.NewEngine(cfg.Risk)
	playbookEngine := playbook.New(playbook.Config{
		LockdownMinutes:   cfg.Playbook.LockdownMinutes,
		StrictModeMinutes: cfg.Playbook.StrictModeMinutes,
		ExitStepSeconds:   cfg.Playbook.ExitStepSeconds,
	}, auditLogger)
	analyticsEngine := analytics.New(store)

	botSvc, err := bot.New(cfg, logger, store, riskEngine, trustEngine, playbookEngine, auditLogger, analyticsEngine)
	if err != nil {
		logger.Fatal("bot init failed", zap.Error(err))
	}

	if err := botSvc.Start(); err != nil {
		logger.Fatal("bot start failed", zap.Error(err))
	}
	logger.Info("bot started")

	var server *http.Server
	if cfg.Health.Enabled {
		server = &http.Server{Addr: cfg.Health.Addr}
		http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})
		go func() {
			logger.Info("health endpoint enabled", zap.String("addr", cfg.Health.Addr))
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("health server error", zap.Error(err))
			}
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logger.Info("shutdown requested")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if server != nil {
		_ = server.Shutdown(ctx)
	}
	botSvc.Close(ctx)
}
