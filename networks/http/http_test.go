package http

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNetwork_ChainHash(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping interactive network tests in short mode.")
	}

	tests := []struct {
		name        string
		host        string
		want        string
		shouldError bool
	}{
		{
			"quicknet",
			"api.drand.sh",
			"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
			false,
		},
		{
			"quicknet-t",
			"http://pl-eu.testnet.drand.sh",
			"cc9c398442737cbd141526600919edd69f1d6f9b4adb67e4d912fbc64341a9a5",
			false,
		},
		{
			"evmnet",
			"https://api2.drand.sh",
			"04f1e9062b8a81f848fded9c12306733282b2727ecced50032187751166ec8c3",
			false,
		},
		{
			"default",
			"https://api2.drand.sh",
			"8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := NewNetwork(tt.host, tt.want)
			if tt.shouldError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if got := n.ChainHash(); got != tt.want {
				t.Errorf("ChainHash() = %v, want %v", got, tt.want)
			}
		})
	}
}
