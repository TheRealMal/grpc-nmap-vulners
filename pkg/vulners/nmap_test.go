package vulners

import (
	"testing"

	"github.com/Ullaakut/nmap"
	"github.com/stretchr/testify/assert"
)

func TestScanWithNmap(t *testing.T) {
	targets := []string{"127.0.0.1"}
	ports := "80,443"

	response, err := ScanWithNmap(targets, ports)
	if err != nil {
		t.Errorf("ScanWithNmap failed: %v", err)
	}
	if response == nil {
		t.Error("ScanWithNmap response is nil")
	}

	assert.Equal(t, response.Results[0].Target, "127.0.0.1")
	if response.Results[0].Services[0].TcpPort == 443 {
		assert.Equal(t, response.Results[0].Services[0].Name, "https")
		assert.Equal(t, response.Results[0].Services[1].Name, "http")
	} else {
		assert.Equal(t, response.Results[0].Services[0].Name, "http")
		assert.Equal(t, response.Results[0].Services[1].Name, "https")
	}
}

func TestVulnFind(t *testing.T) {
	elements := []nmap.Element{
		{Key: "id", Value: "CVE-2021-12345"},
		{Key: "cvss", Value: "7.2"},
		{Key: "description", Value: "A test vulnerability"},
	}
	targetKey := "id"

	result := vulnFind(elements, targetKey)
	expectedResult := "CVE-2021-12345"
	assert.Equal(t, result, expectedResult)

	nonExistentKey := "nonexistent"

	result = vulnFind(elements, nonExistentKey)
	expectedResult = ""
	assert.Equal(t, result, expectedResult)
}
