.PHONY: verify fmt-check proto-check vet test-race build conformance

verify: fmt-check proto-check vet test-race build conformance

fmt-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

proto-check:
	GOWORK=off scripts/test-native-proto-generated.sh

vet:
	GOWORK=off go vet ./...

test-race:
	GOWORK=off go test -race -count=1 ./...

build:
	GOWORK=off go build ./...

# The committed Guarantor conformance corpus must equal what the generator
# emits (compared, never rewritten), and an independent verifier must
# reproduce its registries, digests and native authorization vectors.
GUARANTOR_CORPUS := tests/conformance/agent-guarantor-v1.json
GUARANTOR_SIGNATURE_VECTOR := pkg/agentguarantor/testdata/agent-guarantor-signature-vector.json

conformance:
	GOWORK=off go run ./cmd/agent-guarantor-fixtures -signature-vector $(GUARANTOR_SIGNATURE_VECTOR) | cmp - $(GUARANTOR_CORPUS)
	python3 -I tests/conformance/agent_guarantor_registry_verify.py < $(GUARANTOR_CORPUS)
