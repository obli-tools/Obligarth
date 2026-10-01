// Package app wires the components of apple-edge for the serve command:
// start-up checks, the two listeners, the background jobs and the
// graceful shutdown.
package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/micromdm/nanomdm/service/certauth"
	"github.com/micromdm/nanomdm/service/nanomdm"
	"github.com/micromdm/nanomdm/storage/pgsql"

	"github.com/MeeJay/Obligarth/apple-edge/internal/api"
	"github.com/MeeJay/Obligarth/apple-edge/internal/config"
	"github.com/MeeJay/Obligarth/apple-edge/internal/crypto/envelope"
	"github.com/MeeJay/Obligarth/apple-edge/internal/mdm"
	"github.com/MeeJay/Obligarth/apple-edge/internal/migrate"
	"github.com/MeeJay/Obligarth/apple-edge/internal/obs"
	"github.com/MeeJay/Obligarth/apple-edge/internal/outbox"
	"github.com/MeeJay/Obligarth/apple-edge/internal/queue"
	"github.com/MeeJay/Obligarth/apple-edge/internal/scep"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store"
	"github.com/MeeJay/Obligarth/apple-edge/internal/tenant"
)

// ErrSchema is returned when the database is not at the expected version.
var ErrSchema = errors.New("database schema is not at the version expected by this binary")

// Job periods.
const (
	ReconcileInterval  = 60 * time.Second
	ExpiryInterval     = time.Minute
	PurgeInterval      = time.Hour
	RetentionInterval  = 24 * time.Hour
	CommandRetention   = 30 * 24 * time.Hour
	LimiterSweepPeriod = time.Minute
)

// App is a running apple-edge.
type App struct {
	Cfg      *config.Config
	Logger   *obs.Logger
	Metrics  *obs.Metrics
	DB       *sql.DB
	DSN      string
	Keys     *store.Keyring
	Out      *outbox.Writer
	Registry *tenant.Registry
	Tenants  *tenant.Service
	Queue    *queue.Queue
	Surface  *mdm.Surface
	Verifier *mdm.Verifier
	API      *api.Server
	Health   *api.Health

	DeviceAddr   net.Addr
	InternalAddr net.Addr

	tasks    sync.WaitGroup
	stopJobs context.CancelFunc
	device   *http.Server
	internal *http.Server
}

// Secrets read from files by the caller.
type Secrets struct {
	DBPassword string
	KEK        *envelope.KEK
	APITokens  []string // current first, then next
}

// LoadSecrets reads the secret files named by the configuration.
func LoadSecrets(cfg *config.Config) (Secrets, error) {
	var s Secrets
	var err error
	if s.DBPassword, err = config.ReadSecretFile(cfg.DBPasswordFile); err != nil {
		return s, fmt.Errorf("EDGE_DB_PASSWORD_FILE: %w", err)
	}
	kekText, err := config.ReadSecretFile(cfg.KEKFile)
	if err != nil {
		return s, fmt.Errorf("EDGE_KEK_FILE: %w", err)
	}
	if s.KEK, err = envelope.ParseKEK(kekText); err != nil {
		return s, err
	}
	tok, err := config.ReadSecretFile(cfg.APITokenFile)
	if err != nil {
		return s, fmt.Errorf("EDGE_API_TOKEN_FILE: %w", err)
	}
	s.APITokens = append(s.APITokens, tok)
	if cfg.APITokenNextFile != "" {
		next, err := config.ReadSecretFile(cfg.APITokenNextFile)
		if err != nil {
			return s, fmt.Errorf("EDGE_API_TOKEN_NEXT_FILE: %w", err)
		}
		s.APITokens = append(s.APITokens, next)
	}
	return s, nil
}

// Start performs the start-up sequence and opens both listeners: database
// (waited for up to 60 s), schema version, keys, registry, internal
// listener, device listener, jobs.
func Start(ctx context.Context, cfg *config.Config, sec Secrets, logger *obs.Logger, version string) (*App, error) {
	a := &App{Cfg: cfg, Logger: logger, Metrics: obs.NewMetrics()}
	dsn, err := store.DSN(cfg.DatabaseURL, sec.DBPassword, "nanomdm")
	if err != nil {
		return nil, err
	}
	a.DSN = dsn
	if a.DB, err = store.OpenPool(dsn, cfg.DBMaxConns); err != nil {
		return nil, err
	}
	fail := func(err error) (*App, error) {
		a.DB.Close()
		return nil, err
	}
	if err := store.WaitReady(ctx, a.DB, 60*time.Second, func(err error) {
		logger.Info("msg", "waiting for the database", "err", err)
	}); err != nil {
		return fail(err)
	}
	a.Health = &api.Health{DB: a.DB}
	if err := migrate.Check(ctx, a.DB); err != nil {
		var mm *migrate.MismatchError
		if errors.As(err, &mm) {
			logger.Error("msg", "schema mismatch", "err", err)
			return fail(ErrSchema)
		}
		return fail(err)
	}
	a.Health.SchemaOK.Store(true)
	a.Keys = store.NewKeyring(a.DB, sec.KEK)
	pseudo, err := a.Keys.EnsureInstance(ctx)
	if err != nil {
		return fail(fmt.Errorf("keys: %w", err))
	}
	logger.SetPseudonymKey(pseudo)
	a.Health.KeysOK.Store(true)

	a.Out = outbox.NewWriter(a.DB, a.Metrics)
	upstream, err := pgsql.New(pgsql.WithDB(a.DB), pgsql.WithDeleteCommands(), pgsql.WithLogger(logger.With("component", "nanomdm-storage").Nano()))
	if err != nil {
		return fail(err)
	}
	secrets := store.NewSecrets(a.DB, a.Keys)
	nanoStore := store.NewNanoStore(upstream, secrets)
	scepCfg := scep.Config{DB: a.DB, Out: a.Out, Logger: logger, Metrics: a.Metrics, CertDays: cfg.DeviceCertDays}
	a.Registry = tenant.NewRegistry(a.DB, a.Keys, scepCfg, a.Out, logger, a.Metrics)
	a.Health.Reg = a.Registry
	if err := a.Registry.ReloadAll(ctx); err != nil {
		return fail(fmt.Errorf("registry: %w", err))
	}
	core := nanomdm.New(nanoStore, nanomdm.WithLogger(logger.With("component", "nanomdm").Nano()))
	auth := certauth.New(core, nanoStore, certauth.WithLogger(logger.With("component", "certauth").Nano()))
	guard := mdm.NewGuard(auth, nanoStore, a.DB, a.Out, secrets, cfg.CrossTenantPolicy, logger, a.Metrics, cfg.DBMaxConns)
	a.Verifier = mdm.NewVerifier(a.DB, a.Registry, a.Out, logger, a.Metrics)
	a.Surface = mdm.NewSurface(cfg, a.Registry, guard, a.Verifier, logger, a.Metrics)
	a.Queue = &queue.Queue{DB: a.DB, Upstream: nanoStore, Secrets: secrets, Out: a.Out, Logger: logger}
	a.Tenants = &tenant.Service{Reg: a.Registry, DB: a.DB, Keys: a.Keys, Out: a.Out, Logger: logger,
		CAYears: cfg.CAYears, RetireAfter: cfg.RetireAfter, PublicBase: cfg.PublicBase}
	a.API = &api.Server{Cfg: cfg, DB: a.DB, Tenants: a.Tenants, Reg: a.Registry, Queue: a.Queue, Disabler: nanoStore,
		Secrets: secrets, Out: a.Out, Verifier: a.Verifier, Logger: logger, Metrics: a.Metrics, Health: a.Health, Version: version}
	if err := a.API.SetTokens(sec.APITokens...); err != nil {
		return fail(err)
	}

	errLog := log.New(&maskedWriter{logger: logger}, "", 0)
	internalLn, err := net.Listen("tcp", cfg.InternalListen)
	if err != nil {
		return fail(fmt.Errorf("internal listener: %w", err))
	}
	deviceLn, err := net.Listen("tcp", cfg.DeviceListen)
	if err != nil {
		internalLn.Close()
		return fail(fmt.Errorf("device listener: %w", err))
	}
	a.InternalAddr, a.DeviceAddr = internalLn.Addr(), deviceLn.Addr()
	a.internal = newServer(a.API.Handler(), cfg, errLog)
	a.device = newServer(a.Surface, cfg, errLog)
	jobsCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	a.stopJobs = cancel
	a.serve(a.internal, internalLn, "internal")
	a.serve(a.device, deviceLn, "device")
	a.startJobs(jobsCtx)
	logger.Info("msg", "apple-edge started", "version", version, "count", len(a.Registry.Keys()))
	return a, nil
}

func newServer(h http.Handler, cfg *config.Config, errLog *log.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
		ErrorLog:          errLog,
	}
}

func (a *App) serve(srv *http.Server, ln net.Listener, name string) {
	a.tasks.Add(1)
	go func() {
		defer a.tasks.Done()
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.Logger.Error("msg", "listener stopped", "component", name, "err", err)
		}
	}()
}

func (a *App) every(ctx context.Context, name string, period time.Duration, fn func(context.Context) error) {
	a.tasks.Add(1)
	go func() {
		defer a.tasks.Done()
		t := time.NewTicker(period)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			jctx, cancel := context.WithTimeout(ctx, max(period, time.Minute))
			if err := fn(jctx); err != nil && ctx.Err() == nil {
				a.Logger.Error("msg", "job failed", "component", name, "err", err)
			}
			cancel()
		}
	}()
}

func (a *App) startJobs(ctx context.Context) {
	a.tasks.Add(2)
	go func() { defer a.tasks.Done(); a.Out.Run(ctx, a.Logger) }()
	go func() { defer a.tasks.Done(); a.Registry.Run(ctx, a.DSN, ReconcileInterval) }()
	a.every(ctx, "command-expiry", ExpiryInterval, func(ctx context.Context) error {
		_, err := a.Queue.ExpireDue(ctx)
		return err
	})
	a.every(ctx, "outbox-purge", PurgeInterval, func(ctx context.Context) error {
		_, _, err := outbox.PurgeConsumed(ctx, a.DB, a.Cfg.OutboxRetention)
		return err
	})
	a.every(ctx, "challenge-purge", PurgeInterval, func(ctx context.Context) error {
		_, _, err := scep.PurgeChallenges(ctx, a.DB)
		return err
	})
	a.every(ctx, "command-retention", RetentionInterval, func(ctx context.Context) error {
		_, err := a.Queue.PurgeClosed(ctx, CommandRetention)
		return err
	})
	a.every(ctx, "tenant-retirement", PurgeInterval, func(ctx context.Context) error {
		_, err := a.Tenants.FinalizeRetired(ctx)
		return err
	})
	a.every(ctx, "limiter-sweep", LimiterSweepPeriod, func(context.Context) error {
		a.Surface.SweepLimiters()
		return nil
	})
	since := time.Now().Add(-2 * a.Cfg.SeenBatchInterval)
	a.every(ctx, "seen-batch", a.Cfg.SeenBatchInterval, func(ctx context.Context) error {
		until := time.Now()
		_, ran, err := outbox.SeenBatch(ctx, a.DB, a.Out, a.Registry.Keys(), since, until)
		if err == nil && ran {
			since = until
		}
		return err
	})
}

// Shutdown stops apple-edge: readiness fails first, the proxy is given the
// drain delay to stop sending, then both listeners finish their requests
// (outbox included), the jobs stop and the pools close.
func (a *App) Shutdown(ctx context.Context) error {
	a.Health.Stopping.Store(true)
	a.Logger.Info("msg", "shutting down")
	select {
	case <-time.After(a.Cfg.ShutdownDrain):
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.Cfg.ShutdownTimeout)
	defer cancel()
	var errs []error
	for _, srv := range []*http.Server{a.device, a.internal} {
		if err := srv.Shutdown(sctx); err != nil {
			errs = append(errs, err)
		}
	}
	a.stopJobs()
	done := make(chan struct{})
	go func() { a.tasks.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		errs = append(errs, errors.New("background jobs did not stop in time"))
	}
	errs = append(errs, a.DB.Close())
	a.Logger.Info("msg", "stopped")
	return errors.Join(errs...)
}

// maskedWriter sends the error log of net/http through the log filter.
type maskedWriter struct{ logger *obs.Logger }

func (w *maskedWriter) Write(p []byte) (int, error) {
	w.logger.Info("msg", "http server", "err", string(p))
	return len(p), nil
}

var _ io.Writer = (*maskedWriter)(nil)
