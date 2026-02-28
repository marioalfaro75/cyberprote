package settings

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/go-github/v60/github"
)

// TestGitHubConnection verifies GitHub connectivity by fetching the configured
// organization or user profile. Returns a success message or an error.
func TestGitHubConnection(ctx context.Context, cfg GitHubConfig, token string) (string, error) {
	if token == "" {
		return "", fmt.Errorf("no GitHub token configured")
	}

	httpClient := &http.Client{
		Transport: &tokenTransport{token: token},
	}

	var client *github.Client
	if cfg.APIURL != "" {
		var err error
		client, err = github.NewClient(httpClient).WithEnterpriseURLs(cfg.APIURL, cfg.APIURL)
		if err != nil {
			return "", fmt.Errorf("github enterprise client: %w", err)
		}
	} else {
		client = github.NewClient(httpClient)
	}

	org, _, err := client.Organizations.Get(ctx, cfg.Owner)
	if err != nil {
		// Fall back to user endpoint.
		user, _, err2 := client.Users.Get(ctx, cfg.Owner)
		if err2 != nil {
			return "", fmt.Errorf("get org/user %q: %w", cfg.Owner, err)
		}
		return fmt.Sprintf("Connected to user %s (%s)", user.GetLogin(), user.GetName()), nil
	}

	return fmt.Sprintf("Connected to org %s (%d public repos)", org.GetLogin(), org.GetPublicRepos()), nil
}

// tokenTransport adds an Authorization header to every request.
type tokenTransport struct {
	token string
}

func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req2 := req.Clone(req.Context())
	req2.Header.Set("Authorization", "Bearer "+t.token)
	return http.DefaultTransport.RoundTrip(req2)
}
