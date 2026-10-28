package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		wantAPIKey string
		wantErr    error
	}{
		{
			name:       "valid API key",
			header:     "ApiKey my-api-key",
			wantAPIKey: "my-api-key",
		},
		{
			name:    "missing authorization header",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "missing API key",
			header:  "ApiKey",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "unsupported authorization scheme",
			header:  "Bearer my-api-key",
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			if tt.header != "" {
				headers.Set("Authorization", tt.header)
			}

			gotAPIKey, err := GetAPIKey(headers)
			if tt.wantErr != nil {
				if err == nil || err.Error() != tt.wantErr.Error() {
					t.Fatalf("GetAPIKey() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetAPIKey() unexpected error = %v", err)
			}
			if gotAPIKey != tt.wantAPIKey {
				t.Errorf("GetAPIKey() = %q, want %q", gotAPIKey, tt.wantAPIKey)
			}
		})
	}
}
