// Command apple-edge is the Apple MDM engine of Obligarth: NanoMDM and
// micromdm/scep embedded as libraries, behind a tenant layer.
//
//	apple-edge serve          run the service
//	apple-edge migrate up     create roles, schemas and apply migrations
//	apple-edge healthcheck    query /readyz on the internal listener
//	apple-edge version        print the versions
//	apple-edge kek rotate --operation <uuid>
//	                          re-wrap every DEK with the current KEK
//	apple-edge signing-identity import <chain.pem> <key.pem>
//	                          store the profile signing identity (encrypted)
//
// A refusal caused by the KEK (missing or invalid file, a KEK that does not
// open the database's keys, an interrupted rotation) logs the brain's
// messages at the fatal level and exits with code 1, like the brain.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"runtime/debug"
	"strings"
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
  kek rotate --operation <uuid>
                 re-wrap every data key with EDGE_KEK_FILE (previous: EDGE_KEK_PREVIOUS_FILE);
                 <uuid>: the KEK rotation approved in the console, logged with the rotation
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
	case args[0] == "kek" && len(args) >= 2 && args[1] == "rotate":
		return kekRotate(cfg, logger, args[2:])
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
		if refused(logger, err) || secretFileRefused(logger, err) {
			return 1
		}
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
		if refused(logger, err) {
			return 1
		}
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

// refused logs a refusal caused by the KEK as the brain does (the message,
// then the conclusion, at the fatal level) and reports whether err was one.
// The caller exits with code 1, like the brain.
func refused(logger *obs.Logger, err error) bool {
	r, ok := store.IsKEKRefusal(err)
	if !ok {
		return false
	}
	logger.Fatal(r.Message, "outcome", r.Code)
	logger.Fatal("Keys not ready: refusing to start.")
	return true
}

// secretFileRefused logs a secret file that cannot be used (missing,
// unreadable by uid 65532, malformed) at the fatal level, naming its
// variable, and reports whether err was one. The cause is masked as usual.
func secretFileRefused(logger *obs.Logger, err error) bool {
	var sf *app.SecretFileError
	if !errors.As(err, &sf) {
		return false
	}
	logger.Fatal("The secret file " + sf.Variable + " cannot be used: " + obs.ErrString(sf.Err) + ".")
	logger.Fatal("Secrets not ready: refusing to start.")
	return true
}

func migrateUp(cfg *config.Config, logger *obs.Logger) int {
	if err := cfg.ValidateMigrate(); err != nil {
		logger.Error("msg", "configuration", "err", err)
		return 2
	}
	pw, err := config.ReadSecretFile(cfg.AppDBPasswordFile)
	if err != nil {
		secretFileRefused(logger, &app.SecretFileError{Variable: "EDGE_APP_DB_PASSWORD_FILE", Err: err})
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

// operationRe is the id of a KEK rotation approved in the console (the
// brain's vault_operations id, lower case like the brain's own CLI expects).
var operationRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// operationArg reads --operation <uuid> (or --operation=<uuid>) from args.
func operationArg(args []string) (string, error) {
	op := ""
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--operation" && i+1 < len(args):
			op = args[i+1]
			i++
		case strings.HasPrefix(a, "--operation="):
			op = strings.TrimPrefix(a, "--operation=")
		default:
			return "", fmt.Errorf("unknown argument %q", a)
		}
	}
	if !operationRe.MatchString(op) {
		return "", errors.New("--operation <uuid> is required: the id of the KEK rotation approved (double validation) in the console")
	}
	return op, nil
}

func kekRotate(cfg *config.Config, logger *obs.Logger, args []string) int {
	op, err := operationArg(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "kek rotate:", err)
		return 2
	}
	if err := cfg.ValidateKEKRotate(); err != nil {
		logger.Error("msg", "configuration", "err", err)
		return 2
	}
	pw, err := config.ReadSecretFile(cfg.DBPasswordFile)
	if err != nil {
		secretFileRefused(logger, &app.SecretFileError{Variable: "EDGE_DB_PASSWORD_FILE", Err: err})
		return 1
	}
	current, err := app.LoadKEK(cfg.KEKFile)
	if err != nil {
		refused(logger, err)
		return 1
	}
	prevText, err := config.ReadSecretFile(cfg.KEKPreviousFile)
	if err != nil {
		secretFileRefused(logger, &app.SecretFileError{Variable: "EDGE_KEK_PREVIOUS_FILE", Err: err})
		return 1
	}
	previous, err := envelope.ParseKEK(prevText)
	if err != nil {
		secretFileRefused(logger, &app.SecretFileError{Variable: "EDGE_KEK_PREVIOUS_FILE", Err: err})
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
	// The operation ties the rotation to the double validation recorded by
	// the brain (the same id is given to its vault kek-rotate).
	logger.Info("msg", "KEK rotation started", "operation", op, "previous_kek_id", previous.ID(), "kek_id", current.ID())
	n, err := store.RotateKEK(context.Background(), db, previous, current)
	if err != nil {
		if r, ok := store.IsKEKRefusal(err); ok {
			logger.Fatal(r.Message, "operation", op, "outcome", r.Code, "count", n)
			return 1
		}
		logger.Error("msg", "KEK rotation failed", "operation", op, "count", n, "err", err)
		return 1
	}
	logger.Info("msg", "KEK rotation complete", "operation", op, "previous_kek_id", previous.ID(), "kek_id", current.ID(), "count", n)
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
		secretFileRefused(logger, &app.SecretFileError{Variable: "EDGE_DB_PASSWORD_FILE", Err: err})
		return 1
	}
	kek, err := app.LoadKEK(cfg.KEKFile)
	if err != nil {
		refused(logger, err)
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
	if err := store.CheckKEK(ctx, db, kek); err != nil {
		if !refused(logger, err) {
			logger.Error("msg", "KEK check", "err", err)
		}
		return 1
	}
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
