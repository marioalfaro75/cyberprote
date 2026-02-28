package awssechubreceiver

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	shtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

// SecurityHubAPI defines the interface for Security Hub operations (for testing).
type SecurityHubAPI interface {
	GetFindings(ctx context.Context, params *securityhub.GetFindingsInput, optFns ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error)
}

// secHubReceiver polls AWS Security Hub and emits OCSF-formatted findings.
type secHubReceiver struct {
	cfg          *Config
	logger       *zap.Logger
	nextConsumer consumer.Logs
	client       SecurityHubAPI

	watermark time.Time // last UpdatedAt seen
	cancel    context.CancelFunc
	wg        sync.WaitGroup

	findingsTotal atomic.Int64
	errorsTotal   atomic.Int64
}

func newSecHubReceiver(cfg *Config, logger *zap.Logger, nextConsumer consumer.Logs) (*secHubReceiver, error) {
	return &secHubReceiver{
		cfg:          cfg,
		logger:       logger,
		nextConsumer: nextConsumer,
	}, nil
}

// Start begins polling Security Hub.
func (r *secHubReceiver) Start(ctx context.Context, host component.Host) error {
	if r.client == nil {
		client, err := r.createClient(ctx)
		if err != nil {
			return fmt.Errorf("create Security Hub client: %w", err)
		}
		r.client = client
	}

	pollCtx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel

	r.wg.Add(1)
	go r.poll(pollCtx)

	r.logger.Info("AWS Security Hub receiver started",
		zap.String("region", r.cfg.Region),
		zap.Duration("poll_interval", r.cfg.PollInterval),
	)
	return nil
}

// Shutdown stops the polling loop.
func (r *secHubReceiver) Shutdown(ctx context.Context) error {
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
	return nil
}

func (r *secHubReceiver) createClient(ctx context.Context) (SecurityHubAPI, error) {
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(r.cfg.Region),
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}

	if r.cfg.AssumeRole != "" {
		stsClient := sts.NewFromConfig(cfg)
		provider := stscreds.NewAssumeRoleProvider(stsClient, r.cfg.AssumeRole, func(o *stscreds.AssumeRoleOptions) {
			if r.cfg.ExternalID != "" {
				o.ExternalID = aws.String(r.cfg.ExternalID)
			}
		})
		cfg.Credentials = aws.NewCredentialsCache(provider)
	}

	return securityhub.NewFromConfig(cfg), nil
}

func (r *secHubReceiver) poll(ctx context.Context) {
	defer r.wg.Done()

	ticker := time.NewTicker(r.cfg.PollInterval)
	defer ticker.Stop()

	// Initial poll
	r.fetchFindings(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.fetchFindings(ctx)
		}
	}
}

func (r *secHubReceiver) fetchFindings(ctx context.Context) {
	start := time.Now()

	input := r.buildInput()
	var nextToken *string

	for {
		input.NextToken = nextToken
		output, err := r.client.GetFindings(ctx, input)
		if err != nil {
			r.errorsTotal.Add(1)
			r.logger.Error("failed to get findings", zap.Error(err))
			return
		}

		if len(output.Findings) > 0 {
			if err := r.emitFindings(ctx, output.Findings); err != nil {
				r.errorsTotal.Add(1)
				r.logger.Error("failed to emit findings", zap.Error(err))
			}
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	r.logger.Debug("poll completed",
		zap.Duration("duration", time.Since(start)),
		zap.Int64("total_findings", r.findingsTotal.Load()),
	)
}

func (r *secHubReceiver) buildInput() *securityhub.GetFindingsInput {
	batchSize := r.cfg.BatchSize
	input := &securityhub.GetFindingsInput{
		MaxResults: &batchSize,
	}

	filters := &shtypes.AwsSecurityFindingFilters{}
	hasFilters := false

	// Watermark filter: only get findings updated since last poll
	if !r.watermark.IsZero() {
		rangeVal := int32(1)
		filters.UpdatedAt = []shtypes.DateFilter{
			{
				DateRange: &shtypes.DateRange{
					Value: &rangeVal,
					Unit:  shtypes.DateRangeUnitDays,
				},
			},
		}
		hasFilters = true
	}

	if r.cfg.Filters != nil {
		if len(r.cfg.Filters.SeverityLabels) > 0 {
			for _, label := range r.cfg.Filters.SeverityLabels {
				filters.SeverityLabel = append(filters.SeverityLabel, shtypes.StringFilter{
					Value:      aws.String(label),
					Comparison: shtypes.StringFilterComparisonEquals,
				})
			}
			hasFilters = true
		}

		if r.cfg.Filters.RecordState != "" {
			filters.RecordState = []shtypes.StringFilter{
				{
					Value:      aws.String(r.cfg.Filters.RecordState),
					Comparison: shtypes.StringFilterComparisonEquals,
				},
			}
			hasFilters = true
		}

		if len(r.cfg.Filters.ProductArns) > 0 {
			for _, arn := range r.cfg.Filters.ProductArns {
				filters.ProductArn = append(filters.ProductArn, shtypes.StringFilter{
					Value:      aws.String(arn),
					Comparison: shtypes.StringFilterComparisonEquals,
				})
			}
			hasFilters = true
		}
	}

	if hasFilters {
		input.Filters = filters
	}

	return input
}

func (r *secHubReceiver) emitFindings(ctx context.Context, findings []shtypes.AwsSecurityFinding) error {
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("csf.source.platform", "aws")
	rl.Resource().Attributes().PutStr("cloud.provider", "aws")
	rl.Resource().Attributes().PutStr("csf.receiver", "awssechub")

	sl := rl.ScopeLogs().AppendEmpty()

	for _, finding := range findings {
		ocsfJSON, err := MapASSFToOCSF(&finding)
		if err != nil {
			r.logger.Warn("failed to map ASFF to OCSF",
				zap.String("finding_id", aws.ToString(finding.Id)),
				zap.Error(err),
			)
			continue
		}

		lr := sl.LogRecords().AppendEmpty()
		lr.Body().SetStr(string(ocsfJSON))
		lr.Attributes().PutStr("csf.finding.id", aws.ToString(finding.Id))
		lr.Attributes().PutStr("csf.source.format", "ASFF")

		r.findingsTotal.Add(1)

		// Update watermark
		if finding.UpdatedAt != nil {
			updatedAt, err := time.Parse(time.RFC3339, aws.ToString(finding.UpdatedAt))
			if err == nil && updatedAt.After(r.watermark) {
				r.watermark = updatedAt
			}
		}
	}

	return r.nextConsumer.ConsumeLogs(ctx, ld)
}

// SetClient allows injecting a mock client for testing.
func (r *secHubReceiver) SetClient(client SecurityHubAPI) {
	r.client = client
}

// marshalFinding converts an OCSF finding struct to JSON bytes.
func marshalFinding(finding interface{}) ([]byte, error) {
	return json.Marshal(finding)
}
