package sigchain

import (
	"encoding/json"
	"go-seald-sdk/test_utils"
	"os"
	"path/filepath"
	"testing"
)

type TestFixture struct {
	Blocks     []*Block `json:"sigchain"`
	ErrorCode  *string  `json:"errorCode"`
	StrictMode bool     `json:"strictMode"`
}

func runTestOnFixture(t *testing.T, fixturesDir string, file string) {
	content, err := os.ReadFile(filepath.Join(fixturesDir, file))
	if err != nil {
		t.Log("Error when opening file: ", err)
		t.Fail()
	}

	// Now let's unmarshall the data into `payload`
	var payload TestFixture
	err = json.Unmarshal(content, &payload)
	if err != nil {
		t.Log("Error during Unmarshal(): ", err)
		t.Fail()
	}

	sigchain := Sigchain{Blocks: payload.Blocks}

	_, err = CheckSigchainTransactions(sigchain, payload.StrictMode)

	if err == nil {
		if payload.ErrorCode != nil {
			t.Log(file, "no error happened, expected", *payload.ErrorCode)
			t.Fail()
		}
	} else {
		if payload.ErrorCode == nil {
			t.Log(file, "expected no error, got", err)
			t.Fail()
		} else if *payload.ErrorCode != err.Error() {
			t.Log(file, "errors don't match, expected", *payload.ErrorCode, "got", err)
			t.Fail()
		}
	}
}

func TestSigchain_Fixtures(t *testing.T) {
	fixturesDir := filepath.Join(test_utils.GetCurrentPath(), "fixtures")

	files, err := os.ReadDir(fixturesDir)

	if err != nil {
		t.Log("Error when opening file: ", err)
		t.Fail()
		return
	}

	for _, file := range files {
		t.Log("Testing fixture", file.Name())
		runTestOnFixture(t, fixturesDir, file.Name())
	}
}
