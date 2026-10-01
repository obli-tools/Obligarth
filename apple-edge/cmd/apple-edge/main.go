// Command apple-edge is the Apple MDM engine of Obligarth: NanoMDM and
// micromdm/scep embedded as libraries, behind a tenant layer.
//
//	apple-edge serve          run the service
//	apple-edge migrate up     create roles, schemas and apply migrations
//	apple-edge healthcheck    query /readyz on the internal listener
//	apple-edge version        print the versions
//	apple-edge kek rotate     re-wrap every DEK with the current KEK
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/MeeJay/Obligarth/apple-edge/internal/app"
	"github.com/MeeJay/Obligarth/apple-edge/internal/config"
	"github.com/MeeJay/Obligarth/apple-edge/internal/crypto/envelope"
	"github.com/MeeJay/Obligarth/apple-edge/internal/migrate"
	"github.com/MeeJay/Obligarth/apple-edge/internal/obs"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

const usage = `usage: apple-edge <command>

commands:
  serve          run the service
  migrate up     create roles and schemas, apply the migrations (administration DSN)
  healthcheck    exit 0 if the internal /readyz answers 200
  version        print the versions
  kek rotate     re-wrap every data key with EDGE_KEK_FILE (previous: EDGE_KEK_PREVIOUS_FILE)
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		return 2
	}
	logger := obs.NewLogger(os.Stdout, cfg.LogLevel == "debug")
	switch {
	case args[0] == "serve" && len(args) == 1:
		return serve(cfg, logger)
	case args[0] == "migrate" && len(args) == 2 && args[1] == "up":
		return migrateUp(cfg, logger)
	case args[0] == "healthcheck" && len(args) == 1:
		return healthcheck(cfg)
	case args[0] == "version" && len(args) == 1:
		printVersion()
		return 0
	case args[0] == "kek" && len(args) == 2 && args[1] == "rotate":
		return kekRotate(cfg, logger)
	}
	fmt.Fprint(os.Stderr, usage)
	return 2
}

func serve(cfg *config.Config, logger *obs.Logger) int {
	if err := cfg.ValidateServe(); err != nil {
		logger.Error("msg", "configuration", "err", err)
		return 2
	}
	sec, err := app.LoadSecrets(cfg)
	if err != nil {
		logger.Error("msg", "secrets", "err", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a, err := app.Start(ctx, cfg, sec, logger, version)
	if errors.Is(err, app.ErrSchema) {
		return migrate.ExitCodeSchemaMismatch
	}
	if err != nil {
		logger.Error("msg", "start-up failed", "err", err)
		return 1
	}
	<-ctx.Done()
	if err := a.Shutdown(context.Background()); err != nil {
		logger.Error("msg", "shutdown", "err", err)
		return 1
	}
	return 0
}

func migrateUp(cfg *config.Config, logger *obs.Logger) int {
	if err := cfg.ValidateMigrate(); err != nil {
		logger.Error("msg", "configuration", "err", err)
		return 2
	}
	pw, err := config.ReadSecretFile(cfg.AppDBPasswordFile)
	if err != nil {
		logger.Error("msg", "EDGE_APP_DB_PASSWORD_FILE", "err", err)
		return 1
	}
	db, err := store.OpenPool(cfg.AdminDatabaseURL, 2)
	if err != nil {
		logger.Error("msg", "database", "err", err)
		return 1
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := store.WaitReady(ctx, db, 60*time.Second, nil); err != nil {
		logger.Error("msg", "database", "err", err)
		return 1
	}
	err = migrate.Up(ctx, db, migrate.UpOptions{
		AppPassword:         pw,
		OutboxReaderGrantee: cfg.OutboxReaderGrantee,
		Logf: func(format string, args ...any) {
			logger.Info("msg", fmt.Sprintf(format, args...), "component", "migrate")
		},
	})
	if err != nil {
		logger.Error("msg", "migration failed", "component", "migrate", "err", err)
		return 1
	}
	logger.Info("msg", "migrations up to date", "component", "migrate")
	return 0
}

func healthcheck(cfg *config.Config) int {
	_, port, err := net.SplitHostPort(cfg.InternalListen)
	if err != nil {
		return 1
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/readyz")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func printVersion() {
	fmt.Println("apple-edge", version)
	if bi, ok := debug.ReadBuildInfo(); ok {
		fmt.Println(bi.GoVersion)
		for _, d := range bi.Deps {
			fmt.Println(d.Path, d.Version)
		}
	}
}

func kekRotate(cfg *config.Config, logger *obs.Logger) int {
	if err := cfg.ValidateKEKRotate(); err != nil {
		logger.Error("msg", "configuration", "err", err)
		return 2
	}
	pw, err := config.ReadSecretFile(cfg.DBPasswordFile)
	if err != nil {
		logger.Error("msg", "EDGE_DB_PASSWORD_FILE", "err", err)
		return 1
	}
	read := func(path string) (*envelope.KEK, error) {
		t, err := config.ReadSecretFile(path)
		if err != nil {
			return nil, err
		}
		return envelope.ParseKEK(t)
	}
	current, err := read(cfg.KEKFile)
	if err != nil {
		logger.Error("msg", "EDGE_KEK_FILE", "err", err)
		return 1
	}
	previous, err := read(cfg.KEKPreviousFile)
	if err != nil {
		logger.Error("msg", "EDGE_KEK_PREVIOUS_FILE", "err", err)
		return 1
	}
	dsn, err := store.DSN(cfg.DatabaseURL, pw, "")
	if err != nil {
		logger.Error("msg", "EDGE_DATABASE_URL", "err", err)
		return 1
	}
	db, err := store.OpenPool(dsn, 2)
	if err != nil {
		logger.Error("msg", "database", "err", err)
		return 1
	}
	defer db.Close()
	n, err := store.RotateKEK(context.Background(), db, previous, current)
	if err != nil {
		logger.Error("msg", "KEK rotation", "count", n, "err", err)
		return 1
	}
	logger.Info("msg", "KEK rotation complete", "count", n)
	return 0
}
