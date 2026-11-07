package referencecodec

import (
	"os"
	"testing"
)

func TestIndependentRegistrationVectors(t *testing.T) {
	raw, err := os.ReadFile("../../pkg/nativecore/testdata/native_registry_v1_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	vectors, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := ComputeAgent(vectors)
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, "Agent", agent, vectors.AgentRegistration.Expected)
	capability, err := ComputeCapability(vectors)
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, "Capability", capability, vectors.CapabilityRegistration.Expected)
	for _, mutation := range vectors.NegativeMutations {
		err := CheckNegative(vectors, mutation)
		code, ok := ErrorCodeOf(err)
		if !ok || code != mutation.ExpectedCode {
			t.Errorf("%s/%s: error = %v, code = %d, want %d", mutation.Registration,
				mutation.Mutation, err, code, mutation.ExpectedCode)
		}
	}
}

func assertResult(t *testing.T, name string, actual Result, expected Expected) {
	t.Helper()
	if actual.ObjectID != expected.ObjectID {
		t.Errorf("%s object ID = %q", name, actual.ObjectID)
	}
	if actual.ContractAddress != expected.ContractAddress {
		t.Errorf("%s contract address = %q", name, actual.ContractAddress)
	}
	if actual.ActionHash != expected.ActionHash {
		t.Errorf("%s action hash = %q", name, actual.ActionHash)
	}
	if actual.ActionBOCBase64 != expected.ActionBOCBase64 {
		t.Errorf("%s action BOC = %q", name, actual.ActionBOCBase64)
	}
	if actual.SubmissionBodyHash != expected.SubmissionBody {
		t.Errorf("%s submission body hash = %q", name, actual.SubmissionBodyHash)
	}
}
