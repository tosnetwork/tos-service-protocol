#!/usr/bin/env bash
# Regenerates pkg/nativecore/testdata/escrow_v2_contract_vectors.json by running
# the released stablecoin escrow v2 contract from a TOS checkout on an escrow
# built by this module's Go codec.
#
#   scripts/generate-escrow-v2-vectors.sh <tos-checkout>
#
# 1. cmd/native-escrow-vector builds the escrow StateInit, accept body and
#    Receipt from fixed inputs (it refuses any code but the released v2 code).
# 2. tools/escrow-v2-vectors deploys that StateInit with the frozen escrow
#    code in the TOS sandbox, drives accept, fund, release and refund, and
#    records the data cells, get-method answers, accepted settlement intent and
#    refusal exit codes the contract produces.
#
# Vectors are golden data: regenerate them deliberately, in their own commit,
# and read the diff.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <tos-checkout>" >&2
  exit 2
fi
tos="$(cd "$1" && pwd)"
repo="$(cd "$(dirname "$0")/.." && pwd)"
escrow_boc="$tos/crypto/smartcont/tos-service-stablecoin-escrow-v2.boc.base64"
wallet_boc="$tos/crypto/smartcont/test-usdt-wallet-code.boc.base64"
lock="$tos/tosctl/src/Cargo.lock"
for required in "$escrow_boc" "$wallet_boc" "$lock"; do
  [[ -f "$required" ]] || { echo "missing $required" >&2; exit 1; }
done
commit="$(git -C "$tos" rev-parse HEAD)"
if [[ -n "$(git -C "$tos" status --porcelain -- crypto/smartcont tosctl/src/sandbox tosctl/src/block)" ]]; then
  echo "TOS checkout has uncommitted changes under the contract or sandbox sources" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/crate/src"
sed "s#@TOS@#$tos#g" "$repo/tools/escrow-v2-vectors/Cargo.toml.in" > "$work/crate/Cargo.toml"
cp "$repo/tools/escrow-v2-vectors/src/main.rs" "$work/crate/src/main.rs"
cp "$lock" "$work/crate/Cargo.lock"

repeat() { printf "$1%.0s" $(seq 1 32); }
(cd "$repo" && GOWORK=off go run ./cmd/native-escrow-vector \
  --escrow-code "$escrow_boc" --wallet-code "$wallet_boc" \
  --buyer "0:$(repeat b1)" --provider "0:$(repeat 9e)" --master "0:$(repeat 5a)" \
  --base-unix 1800000000 --signer-seed "$(repeat 51)") > "$work/input.json"

target="${CARGO_TARGET_DIR:-$work/target}"
CARGO_TARGET_DIR="$target" cargo run --quiet --release --manifest-path "$work/crate/Cargo.toml" -- \
  "$tos" "$commit" "$work/input.json" > "$work/vectors.json"
mv "$work/vectors.json" "$repo/pkg/nativecore/testdata/escrow_v2_contract_vectors.json"
echo "wrote pkg/nativecore/testdata/escrow_v2_contract_vectors.json from TOS $commit"
