// Command apple-edge is the Apple MDM engine of Obligarth: NanoMDM and
// micromdm/scep embedded as libraries, behind a tenant layer.
//
//	apple-edge serve          run the service
//	apple-edge migrate up     create roles, schemas and apply migrations
//	apple-edge healthcheck    query /readyz on the internal listener
//	apple-edge version        print the versions
//	apple-edge kek rotate     re-wrap every DEK with the current KEK
//	apple-edge signing-identity import <chain.pem> <key.pem>
//	                          store the profile signing identity (encrypted)
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
	"github.com/MeeJay/Obligarth/apple-edge/internal/signing"
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
  signing-identity import <chain.pem> <key.pem>
                 store the profile signing identity (chain: leaf first), key encrypted
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
	case args[0] == "signing-identity" && len(args) == 4 && args[1] == "import":
		return signingImport(cfg, logger, args[2], args[3])
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

func signingImport(cfg *config.Config, logger *obs.Logger, chainFile, keyFile string) int {
	if err := cfg.ValidateSigningImport(); err != nil {
		logger.Error("msg", "configuration", "err", err)
		return 2
	}
	chain, err := os.ReadFile(chainFile)
	if err != nil {
		logger.Error("msg", "certificate chain file", "err", err)
		return 1
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		logger.Error("msg", "private key file", "err", err)
		return 1
	}
	id, err := signing.ParseIdentity(chain, key, time.Now())
	if err != nil {
		logger.Error("msg", "signing identity", "err", err)
		return 1
	}
	pw, err := config.ReadSecretFile(cfg.DBPasswordFile)
	if err != nil {
		logger.Error("msg", "EDGE_DB_PASSWORD_FILE", "err", err)
		return 1
	}
	kekText, err := config.ReadSecretFile(cfg.KEKFile)
	if err != nil {
		logger.Error("msg", "EDGE_KEK_FILE", "err", err)
		return 1
	}
	kek, err := envelope.ParseKEK(kekText)
	if err != nil {
		logger.Error("msg", "EDGE_KEK_FILE", "err", err)
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	keys := store.NewKeyring(db, kek)
	if _, err := keys.EnsureInstance(ctx); err != nil {
		logger.Error("msg", "instance data key (KEK check)", "err", err)
		return 1
	}
	if err := signing.Import(ctx, db, keys, id); err != nil {
		logger.Error("msg", "signing identity import", "err", err)
		return 1
	}
	logger.Info("msg", "profile signing identity imported", "count", len(id.Chain))
	return 0
}
