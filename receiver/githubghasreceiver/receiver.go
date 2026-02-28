package githubghasreceiver

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/go-github/v60/github"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

// ghasReceiver polls GitHub GHAS endpoints and emits OCSF findings.
type ghasReceiver struct {
	cfg          *Config
	logger       *zap.Logger
	nextConsumer consumer.Logs
	ghClient     *github.Client

	cancel context.CancelFunc
	wg     sync.WaitGroup

	findingsTotal atomic.Int64
	errorsTotal   atomic.Int64
}

func newGHASReceiver(cfg *Config, logger *zap.Logger, nextConsumer consumer.Logs) (*ghasReceiver, error) {
	return &ghasReceiver{
		cfg:          cfg,
		logger:       logger,
		nextConsumer: nextConsumer,
	}, nil
}

// Start begins polling GitHub GHAS.
func (r *ghasReceiver) Start(ctx context.Context, host component.Host) error {
	if r.ghClient == nil {
		r.ghClient = r.createClient()
	}

	pollCtx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel

	r.wg.Add(1)
	go r.poll(pollCtx)

	r.logger.Info("GitHub GHAS receiver started",
		zap.String("owner", r.cfg.Owner),
		zap.Duration("poll_interval", r.cfg.PollInterval),
	)
	return nil
}

// Shutdown stops the polling loop.
func (r *ghasReceiver) Shutdown(ctx context.Context) error {
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
	return nil
}

func (r *ghasReceiver) createClient() *github.Client {
	client := github.NewClient(nil)
	if r.cfg.Token != "" {
		client = client.WithAuthToken(r.cfg.Token)
	}
	if r.cfg.APIURL != "" {
		var err error
		client, err = client.WithEnterpriseURLs(r.cfg.APIURL, r.cfg.APIURL)
		if err != nil {
			r.logger.Error("failed to configure enterprise URL", zap.Error(err))
		}
	}
	return client
}

// SetClient allows injecting a mock client for testing.
func (r *ghasReceiver) SetClient(client *github.Client) {
	r.ghClient = client
}

func (r *ghasReceiver) poll(ctx context.Context) {
	defer r.wg.Done()

	ticker := time.NewTicker(r.cfg.PollInterval)
	defer ticker.Stop()

	r.fetchAlerts(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.fetchAlerts(ctx)
		}
	}
}

func (r *ghasReceiver) fetchAlerts(ctx context.Context) {
	repos := r.cfg.Repos
	if len(repos) == 0 {
		r.logger.Debug("no repos configured, skipping poll")
		return
	}

	for _, repo := range repos {
		if r.cfg.EnableCodeScanning {
			r.fetchCodeScanningAlerts(ctx, repo)
		}
		if r.cfg.EnableDependabot {
			r.fetchDependabotAlerts(ctx, repo)
		}
		if r.cfg.EnableSecretScanning {
			r.fetchSecretScanningAlerts(ctx, repo)
		}
	}
}

func (r *ghasReceiver) fetchCodeScanningAlerts(ctx context.Context, repo string) {
	opts := &github.AlertListOptions{
		State: "open",
		ListOptions: github.ListOptions{PerPage: 100},
	}

	alerts, _, err := r.ghClient.CodeScanning.ListAlertsForRepo(ctx, r.cfg.Owner, repo, opts)
	if err != nil {
		r.errorsTotal.Add(1)
		r.logger.Error("failed to fetch code scanning alerts",
			zap.String("repo", repo), zap.Error(err))
		return
	}

	if len(alerts) == 0 {
		return
	}

	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("csf.source.platform", "github")
	rl.Resource().Attributes().PutStr("csf.receiver", "githubghas")
	rl.Resource().Attributes().PutStr("github.owner", r.cfg.Owner)
	rl.Resource().Attributes().PutStr("github.repo", repo)

	sl := rl.ScopeLogs().AppendEmpty()
	for _, alert := range alerts {
		ocsfJSON, err := MapCodeScanningToOCSF(alert, r.cfg.Owner, repo)
		if err != nil {
			r.logger.Warn("failed to map code scanning alert", zap.Error(err))
			continue
		}
		lr := sl.LogRecords().AppendEmpty()
		lr.Body().SetStr(string(ocsfJSON))
		lr.Attributes().PutStr("csf.source.format", "github_code_scanning")
		r.findingsTotal.Add(1)
	}

	if err := r.nextConsumer.ConsumeLogs(ctx, ld); err != nil {
		r.errorsTotal.Add(1)
		r.logger.Error("failed to emit code scanning logs", zap.Error(err))
	}
}

func (r *ghasReceiver) fetchDependabotAlerts(ctx context.Context, repo string) {
	opts := &github.ListAlertsOptions{
		State:       github.String("open"),
		ListOptions: github.ListOptions{PerPage: 100},
	}

	alerts, _, err := r.ghClient.Dependabot.ListRepoAlerts(ctx, r.cfg.Owner, repo, opts)
	if err != nil {
		r.errorsTotal.Add(1)
		r.logger.Error("failed to fetch dependabot alerts",
			zap.String("repo", repo), zap.Error(err))
		return
	}

	if len(alerts) == 0 {
		return
	}

	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("csf.source.platform", "github")
	rl.Resource().Attributes().PutStr("csf.receiver", "githubghas")
	rl.Resource().Attributes().PutStr("github.owner", r.cfg.Owner)
	rl.Resource().Attributes().PutStr("github.repo", repo)

	sl := rl.ScopeLogs().AppendEmpty()
	for _, alert := range alerts {
		ocsfJSON, err := MapDependabotToOCSF(alert, r.cfg.Owner, repo)
		if err != nil {
			r.logger.Warn("failed to map dependabot alert", zap.Error(err))
			continue
		}
		lr := sl.LogRecords().AppendEmpty()
		lr.Body().SetStr(string(ocsfJSON))
		lr.Attributes().PutStr("csf.source.format", "github_dependabot")
		r.findingsTotal.Add(1)
	}

	if err := r.nextConsumer.ConsumeLogs(ctx, ld); err != nil {
		r.errorsTotal.Add(1)
		r.logger.Error("failed to emit dependabot logs", zap.Error(err))
	}
}

func (r *ghasReceiver) fetchSecretScanningAlerts(ctx context.Context, repo string) {
	opts := &github.SecretScanningAlertListOptions{
		State:       "open",
		ListOptions: github.ListOptions{PerPage: 100},
	}

	alerts, _, err := r.ghClient.SecretScanning.ListAlertsForRepo(ctx, r.cfg.Owner, repo, opts)
	if err != nil {
		r.errorsTotal.Add(1)
		r.logger.Error("failed to fetch secret scanning alerts",
			zap.String("repo", repo), zap.Error(err))
		return
	}

	if len(alerts) == 0 {
		return
	}

	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("csf.source.platform", "github")
	rl.Resource().Attributes().PutStr("csf.receiver", "githubghas")
	rl.Resource().Attributes().PutStr("github.owner", r.cfg.Owner)
	rl.Resource().Attributes().PutStr("github.repo", repo)

	sl := rl.ScopeLogs().AppendEmpty()
	for _, alert := range alerts {
		ocsfJSON, err := MapSecretScanningToOCSF(alert, r.cfg.Owner, repo)
		if err != nil {
			r.logger.Warn("failed to map secret scanning alert", zap.Error(err))
			continue
		}
		lr := sl.LogRecords().AppendEmpty()
		lr.Body().SetStr(string(ocsfJSON))
		lr.Attributes().PutStr("csf.source.format", "github_secret_scanning")
		r.findingsTotal.Add(1)
	}

	if err := r.nextConsumer.ConsumeLogs(ctx, ld); err != nil {
		r.errorsTotal.Add(1)
		r.logger.Error("failed to emit secret scanning logs", zap.Error(err))
	}
}
