package settings

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// TestAWSConnection verifies AWS connectivity by calling sts:GetCallerIdentity.
// If AssumeRole is set, it first assumes that role.
func TestAWSConnection(ctx context.Context, cfg AWSConfig) (string, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region))
	if err != nil {
		return "", fmt.Errorf("load AWS config: %w", err)
	}

	if cfg.AssumeRole != "" {
		stsClient := sts.NewFromConfig(awsCfg)
		creds := stscreds.NewAssumeRoleProvider(stsClient, cfg.AssumeRole, func(o *stscreds.AssumeRoleOptions) {
			if cfg.ExternalID != "" {
				o.ExternalID = &cfg.ExternalID
			}
		})
		awsCfg.Credentials = creds
	}

	stsClient := sts.NewFromConfig(awsCfg)
	out, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("sts:GetCallerIdentity: %w", err)
	}

	return fmt.Sprintf("Authenticated as %s (Account: %s)", *out.Arn, *out.Account), nil
}
