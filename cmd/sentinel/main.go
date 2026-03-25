package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sentinel-adaptive/internal/analytics"
	"sentinel-adaptive/internal/bot"
	"sentinel-adaptive/internal/config"
	"sentinel-adaptive/internal/dashboard"
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

	if cfg.DatabaseURL == "" {
		logger.Fatal("DATABASE_URL is required (PostgreSQL connection string)")
	}

	store, err := storage.New(cfg.DatabaseURL)
	if err != nil {
		logger.Fatal("storage init failed", zap.Error(err))
	}
	defer store.Close()
	if steps, ok := parseDownArg(); ok {
		if err := store.MigrateDown(steps); err != nil {
			logger.Fatal("migration rollback failed", zap.Error(err), zap.Int("steps", steps))
		}
		logger.Info("rollback complete", zap.Int("steps", steps))
		return
	}
	if err := store.MigrateUp(); err != nil {
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

	var healthServer *http.Server
	if cfg.Health.Enabled {
		mux := http.NewServeMux()
		mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})
		healthServer = &http.Server{Addr: cfg.Health.Addr, Handler: mux}
		go func() {
			logger.Info("health endpoint enabled", zap.String("addr", cfg.Health.Addr))
			if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("health server error", zap.Error(err))
			}
		}()
	}

	var dashServer *http.Server
	if cfg.Dashboard.Addr != "" {
		dashSrv, err := dashboard.New(cfg, store, botSvc.Session(), logger)
		if err != nil {
			logger.Fatal("dashboard init failed", zap.Error(err))
		}
		dashServer = &http.Server{
			Addr:         cfg.Dashboard.Addr,
			Handler:      dashSrv,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 30 * time.Second,
		}
		go func() {
			logger.Info("dashboard started", zap.String("addr", cfg.Dashboard.Addr))
			if err := dashServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("dashboard error", zap.Error(err))
			}
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logger.Info("shutdown requested")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if healthServer != nil {
		_ = healthServer.Shutdown(ctx)
	}
	if dashServer != nil {
		_ = dashServer.Shutdown(ctx)
	}
	botSvc.Close(ctx)
}

// parseDownArg parses --down N or --down=N from os.Args.
// Returns (steps, true) if the flag is present, (0, false) otherwise.
// If N is missing or invalid, defaults to 1.
func parseDownArg() (int, bool) {
	args := os.Args[1:]
	for i, arg := range args {
		switch {
		case arg == "--down":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 {
					return n, true
				}
			}
			return 1, true
		case strings.HasPrefix(arg, "--down="):
			n, err := strconv.Atoi(arg[len("--down="):])
			if err == nil && n > 0 {
				return n, true
			}
			return 1, true
		}
	}
	return 0, false
}
