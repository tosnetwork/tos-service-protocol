#!/usr/bin/env python3
"""Local acceptance of the Service Actor buyer flow on an isolated PQ network.

Boots three ML-DSA-44 PQ validators, each serving JSON-RPC on loopback, then:

1. registers a provider Agent in the Native Registry (ML-DSA-44 controller);
2. deploys a Service Actor with an ML-DSA-44 attestor controller;
3. registers a Capability whose software-work manifest names that actor in
   key 21, and points the actor's metadata_hash at the Capability version;
4. the buyer discovers, verifies and calls through `tos-service-buyer`;
5. the provider responds with an attestor-signed `agent service send
   --operation respond --attestor-controller`;
6. the buyer resolves the request as responded;
7. refused cases: discovery pinned to another actor code hash, and a call
   prepared under terms the provider changed before the call.

Stand-ins, both local and authority-free: the manifest store is a directory
of canonical CBOR files named by digest, and the Quote Proposal comes from
`service-actor-e2e-fixture quote`, which runs pkg/quoteprovider against
finalized state instead of a provider gateway.

Run it through scripts/service-actor-buyer-e2e.sh, which places the network
in its own process group under the thermal guard. The run ends with an
evidence file and one ALL PASS or FAIL line.
"""

import asyncio
import datetime
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from service_actor_e2e_redact import redact, redact_value, register_secret, run_logged  # noqa: E402
SOURCE = Path(os.environ["TOS_SOURCE"])
BUILD = Path(os.environ["TOS_BUILD"])
TOSCTL = Path(os.environ["TOSCTL"])
BIN = Path(os.environ["E2E_BIN"])
WORK = Path(os.environ["E2E_WORKDIR"])
REGISTRY_BOC = Path(os.environ["REGISTRY_CODE_BOC"])
ACTOR_CODE_HASH = os.environ["ACTOR_CODE_HASH"]
BASE_PORT = int(os.environ["E2E_BASE_PORT"])
RPC_PORTS = [int(port) for port in os.environ["E2E_RPC_PORTS"].split(",")]
# The registry identity domain names the chain by its global id.
NETWORK_LABEL = os.environ.get("E2E_NETWORK_LABEL", "tos:global-id:3")
MASTER_KEY = secrets.token_hex(32)
NANO = 1_000_000_000

os.umask(0o077)
os.environ.setdefault("RAYON_NUM_THREADS", "2")
os.environ.setdefault("TOKIO_WORKER_THREADS", "2")
# Version 16 genesis binds wallet authorization to one network: a fresh tag.
os.environ["TOS_AUTH_NETWORK_TAG"] = secrets.token_hex(32)

steps: list[dict] = []
PRIVATE = WORK / "private"
CONFIG = PRIVATE / "tosctl-config.json"
VAULT_URL = f"file://{PRIVATE}/vault.json?master_key={MASTER_KEY}"
register_secret(MASTER_KEY)
register_secret(VAULT_URL)
TRANSCRIPT = WORK / "cli-transcript.jsonl"


def record(name: str, ok: bool, detail=None) -> None:
    detail = redact_value(detail)
    steps.append({"name": name, "pass": bool(ok), "detail": detail,
                  "at": datetime.datetime.now(datetime.timezone.utc).isoformat()})
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  {redact(str(detail))}"), flush=True)


def run(command: list[str], *, check: bool = True, timeout: int = 240, env_extra=None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["VAULT_URL"] = VAULT_URL
    if env_extra:
        env.update(env_extra)
    return run_logged(command, TRANSCRIPT, env=env, check=check, timeout=timeout)


def tosctl(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return run([str(TOSCTL), *args, "-c", str(CONFIG)], check=check)


def tosctl_json(*args: str):
    return json.loads(tosctl(*args, "--format", "json").stdout)


def last_json(text: str):
    """The JSON object a tool printed last (tosctl may print text before it)."""
    start = text.find("{")
    return json.loads(text[start:]) if start >= 0 else None


def rpc_endpoints() -> list[str]:
    return [f"http://127.0.0.1:{port}/jsonRPC" for port in RPC_PORTS]


def rpc(method: str, **params):
    import urllib.request
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(rpc_endpoints()[0], data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        raw = response.read()
    # The raw responses are kept so the served shapes (for example storage_stat)
    # can be checked against the decoders; they carry no secret.
    with (WORK / "rpc-transcript.jsonl").open("a") as transcript:
        transcript.write(json.dumps({"method": method, "params": params, "response": redact(raw.decode())}) + "\n")
    return json.loads(raw)


def poll(predicate, timeout: float, interval: float = 2.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = predicate()
            if last:
                return last
        except Exception as error:  # noqa: BLE001 - polled reads retry
            last = error
        time.sleep(interval)
    return None


def common_flags(state: str, actor_code_hash: str = ACTOR_CODE_HASH) -> list[str]:
    return ["--network-domain", str(WORK / "network-domain.json"), "--rpc", ",".join(rpc_endpoints()),
            "--registry-code-boc", str(REGISTRY_BOC), "--registry-code-hash", REGISTRY_CODE_HASH,
            "--actor-code-hash", actor_code_hash, "--state-dir", str(PRIVATE / state),
            "--manifest-dir", str(WORK / "manifests"), "--buyer-wallet", BUYER]


def buyer(*args: str, state: str = "buyer", actor_code_hash: str = ACTOR_CODE_HASH, check: bool = True):
    return run([str(BIN / "tos-service-buyer"), args[0], *common_flags(state, actor_code_hash), *args[1:]], check=check)


def buyer_retry(*args: str, timeout: float = 180, **kwargs):
    """Read-only buyer commands retry while endpoints catch up to one quorum."""
    result = poll(lambda: (lambda r: r if r.returncode == 0 else None)(buyer(*args, check=False, **kwargs)), timeout, 3)
    if result is None:
        raise RuntimeError(f"tos-service-buyer {args[0]} never succeeded")
    return json.loads(result.stdout)


def status_of(request_hash: str) -> dict:
    """One status read; a failure is kept so the evidence shows why."""
    result = buyer("status", "--request-hash", request_hash, check=False)
    if result.returncode != 0:
        LAST_STATUS_ERROR[0] = result.stderr.strip()[-600:]
        return {}
    return json.loads(result.stdout)


LAST_STATUS_ERROR = [None]


def fixture(*args: str) -> dict:
    return json.loads(run([str(BIN / "service-actor-e2e-fixture"), *args]).stdout)


def norm(address: str) -> str:
    from pytosiq_core import Address
    return Address(address).to_str(is_user_friendly=False).lower()


def wallet_address(name: str) -> str:
    for entry in tosctl_json("wallet", "ls"):
        if entry["name"] == name and entry.get("address"):
            return norm(entry["address"])
    raise RuntimeError(f"wallet {name} has no address")


def service_show(address: str) -> dict:
    return tosctl_json("agent", "service", "show", "--address", address)


def registry_show(address: str) -> dict:
    return tosctl_json("agent", "native-registry", "show", "--global-config", str(GLOBAL_CONFIG),
                       "--network-label", NETWORK_LABEL, "--address", address)


def send_registry(view: dict, sender: str) -> None:
    args = ["wallet", "send", "--from", sender, "--to", view["destination"], "--amount", "2",
            "--body-boc", view["body_boc"], "--yes"]
    if view.get("state_init_boc"):
        args += ["--state-init-boc", view["state_init_boc"]]
    tosctl(*args)


def update_policy(actor: str, metadata: str, scheme: str, price: str) -> None:
    tosctl("agent", "service", "send", "--operation", "update-policy", "--address", actor, "--from", "provider",
           "--price-per-call", price, "--storage-fee", "0.2", "--cleanup-bounty", "0.1", "--response-sla", "3600",
           "--refund-claim-window", "3600", "--active", "true", "--open-access", "--rate-limit-per-day", "0",
           "--metadata-hash", metadata, "--proof-scheme-hash", scheme, "--yes")


async def provision(faucet) -> None:
    from contract import tos
    from pytosiq_core import Address, Cell, InternalMsgInfo, MessageAny, WalletMessage

    run([str(TOSCTL), "config", "generate", "-o", str(CONFIG), "--force"])
    config = json.loads(CONFIG.read_text())
    config["chain_rpc"] = {"urls": [f"http://127.0.0.1:{port}" for port in RPC_PORTS], "api_key": None}
    config["elections"] = None
    CONFIG.write_text(json.dumps(config, indent=2))
    for name in ("provider", "buyer"):
        tosctl("wallet", "create", "-n", name, "-v", "V3R2", "-w", "0")
    for name in ("provider", "buyer"):
        address = wallet_address(name)
        await faucet.send(WalletMessage(send_mode=3, message=MessageAny(
            info=InternalMsgInfo(ihr_disabled=True, bounce=False, bounced=False, src=faucet.address, dest=Address(address),
                                 value=tos(60), ihr_fee=0, fwd_fee=0, created_lt=0, created_at=0),
            init=None, body=Cell.empty())))
        funded = poll(lambda a=address: int(rpc("getAddressInformation", address=a)["result"]["balance"]) >= 59 * NANO, 120)
        record(f"{name} wallet funded", bool(funded), address)
        tosctl("wallet", "activate", "-n", name)
        active = poll(lambda a=address: rpc("getAddressState", address=a).get("result") == "active", 120)
        record(f"{name} wallet active", bool(active), address)


def acceptance() -> None:
    global BUYER, REGISTRY_CODE_HASH
    REGISTRY_CODE_HASH = fixture("code-hash", "--boc-file", str(REGISTRY_BOC))["code_hash"]
    provider = wallet_address("provider")
    BUYER = wallet_address("buyer")
    evidence["wallets"] = {"provider": provider, "buyer": BUYER}

    # 1. Provider Agent with an ML-DSA-44 controller.
    controller = tosctl_json("agent", "native-registry", "new-controller", "--name", "provider-controller")
    attestor = tosctl_json("agent", "native-registry", "new-controller", "--name", "service-attestor")
    attestor_text = "mldsa44:" + attestor["key_id"]
    policy_path = PRIVATE / "provider-policy.json"
    policy_path.write_text(json.dumps({"threshold": 1, "recovery_threshold": 1, "recovery_timelock": 3600,
                                       "controllers": [{"public_key": controller["public_key"], "weight": 1, "purposes": 15}]}))
    registration = tosctl_json("agent", "native-registry", "register-agent", "--global-config", str(GLOBAL_CONFIG),
                               "--network-label", NETWORK_LABEL, "--policy", str(policy_path),
                               "--nonce", secrets.token_hex(32), "--signer", "provider-controller")
    send_registry(registration, "provider")
    agent_address = registration["destination"]
    agent_id = "agent_" + registration["object_id"]
    registered = poll(lambda: registry_show(agent_address).get("registered"), 180, 3)
    record("provider Agent registered in the Native Registry", bool(registered), {"agent_id": agent_id, "address": agent_address})

    # 2. Service Actor with an ML-DSA-44 attestor; metadata comes after the
    #    Capability exists, so it starts as zero.
    deploy = last_json(tosctl("agent", "service", "deploy", "--name", "svc", "--owner", provider, "--open-access",
                              "--price-per-call", "0.1", "--storage-fee", "0.2", "--cleanup-bounty", "0.1",
                              "--response-sla", "3600", "--refund-claim-window", "3600", "--rate-limit-per-day", "0",
                              "--metadata-hash", "00" * 32, "--proof-scheme-hash", "00" * 32,
                              "--attestor-controller", "service-attestor", "--from", "provider", "--amount", "3",
                              "-w", "0", "--yes", "--format", "json").stdout)
    actor = norm(deploy["address"])
    deployed = poll(lambda: rpc("getAddressState", address=actor).get("result") == "active", 180, 3)
    record("Service Actor deployed with an ML-DSA-44 attestor", bool(deployed) and
           service_show(actor).get("attestor_key_id") == attestor_text, {"actor": actor, "attestor": attestor_text})
    code = rpc("getAddressInformation", address=actor)["result"]["code"]
    (WORK / "actor-code.boc.base64").write_text(code)
    actual_code_hash = fixture("code-hash", "--boc-file", str(WORK / "actor-code.boc.base64"))["code_hash"]
    record("deployed actor runs the pinned release code", actual_code_hash == ACTOR_CODE_HASH,
           {"account": actual_code_hash, "pinned": ACTOR_CODE_HASH})

    # 3. Capability whose manifest key 21 names the actor.
    manifest = fixture("manifest", "--actor", actor, "--code-hash", ACTOR_CODE_HASH, "--attestor", attestor_text,
                       "--version", "1.0.0", "--out-dir", str(WORK / "manifests"))
    digest = manifest["manifest_digest"]
    capability = tosctl_json("agent", "native-registry", "action", "--global-config", str(GLOBAL_CONFIG),
                             "--network-label", NETWORK_LABEL, "--kind", "register-capability", "--agent", agent_address,
                             "--nonce", secrets.token_hex(32), "--object-nonce", secrets.token_hex(32), "--version", "1.0.0",
                             "--manifest", digest.removeprefix("sha256:"), "--signer", "provider-controller")
    send_registry(capability, "provider")
    capability_address = capability["final_target"]
    registered = poll(lambda: registry_show(capability_address).get("registered"), 180, 3)
    capability_id = "cap_" + registry_show(capability_address)["object_id"]
    record("Capability registered with the key 21 manifest", bool(registered),
           {"capability_id": capability_id, "address": capability_address, "manifest_digest": digest})
    metadata = fixture("metadata", "--network-domain", str(WORK / "network-domain.json"), "--capability-id", capability_id,
                       "--provider-agent-id", agent_id, "--version", "1.0.0", "--manifest-digest", digest)
    update_policy(actor, metadata["metadata_hash"], metadata["proof_scheme_hash"], "0.1")
    configured = poll(lambda: service_show(actor).get("metadata_hash", "").endswith(metadata["metadata_hash"]), 180, 3)
    record("actor metadata_hash is NSM1 of the Capability version", bool(configured), metadata)
    evidence["objects"] = {"agent_id": agent_id, "agent_address": agent_address, "capability_id": capability_id,
                           "capability_address": capability_address, "actor": actor, "manifest_digest": digest,
                           "attestor": attestor_text, "metadata_hash": metadata["metadata_hash"]}

    # Refused: discovery pinned to another code hash.
    other = "tvm-cell-sha256:" + hashlib.sha256(b"not the release").hexdigest()
    wrong = buyer("discover", "--capability-id", capability_id, "--version", "1.0.0", state="wrong-code",
                  actor_code_hash=other, check=False)
    record("discovery pinned to another actor code hash is refused", wrong.returncode != 0 and "code hash" in wrong.stderr,
           wrong.stderr.strip()[-400:])

    # 4. Discover, verify, prepare and call.
    offer = buyer_retry("discover", "--capability-id", capability_id, "--version", "1.0.0")
    record("buyer discovered and verified the offer", offer.get("actor") == actor and offer.get("attestor_key_id") == attestor_text,
           offer)
    package_path = PRIVATE / "quote-1.json"
    quote = fixture("quote", "--network-domain", str(WORK / "network-domain.json"), "--rpc", ",".join(rpc_endpoints()),
                    "--registry-code-boc", str(REGISTRY_BOC), "--registry-code-hash", REGISTRY_CODE_HASH,
                    "--code-hash", ACTOR_CODE_HASH, "--state-dir", str(PRIVATE / "provider-quote"),
                    "--manifest", manifest["path"], "--capability-id", capability_id, "--provider-agent-id", agent_id,
                    "--buyer-wallet", BUYER, "--out", str(package_path))
    record("provider quoted the finalized actor terms", quote.get("terms_hash") == offer.get("terms_hash"), quote)
    prepared = json.loads(buyer("prepare", "--package", str(package_path), "--execution-id", secrets.token_hex(32),
                                "--input-digest", secrets.token_hex(32)).stdout)
    record("buyer prepared the call", prepared.get("phase") == "prepared", {k: prepared.get(k) for k in
           ("request_hash", "query_id", "terms_hash", "payment_nanotos")})
    request_hash = prepared["request_hash"]
    call_flags = ["--request-hash", request_hash, "--tosctl", str(TOSCTL), "--tosctl-sha256", TOSCTL_SHA256,
                  "--tosctl-config", str(CONFIG), "--wallet", "buyer", "--vault-url", VAULT_URL]
    called = buyer("call", *call_flags, check=False)
    called_record = last_json(called.stdout) or {}
    record("buyer called through tosctl agent service send with the quoted terms hash",
           called.returncode == 0 and called_record.get("phase") == "submitted", called.stderr.strip()[-600:])
    status = poll(lambda: (lambda r: r if r.get("found") and r.get("state") == "pending" else None)(
        status_of(request_hash)), 240, 4)
    record("the finalized call is admitted and pending, verified from its snapshot", bool(status),
           status or LAST_STATUS_ERROR[0])
    if not status:
        return
    request_id = status["request_id"]

    # 5. Attestor-signed respond by the provider.
    response_hash = secrets.token_hex(32)
    tosctl("agent", "service", "send", "--operation", "respond", "--address", actor, "--from", "provider",
           "--request-id", str(request_id), "--response-hash", response_hash, "--attestor-controller", "service-attestor", "--yes")
    responded = poll(lambda: (lambda r: r if r.get("state") == "responded" else None)(
        status_of(request_hash)), 240, 4)
    record("the buyer resolves the request as responded with the attested response hash",
           bool(responded) and responded.get("response_hash") == response_hash, responded or LAST_STATUS_ERROR[0])
    requests = buyer_retry("requests", "--actor", actor, "--caller", BUYER)
    record("the rebuilt request index shows the responded request", any(
        r["request_id"] == request_id and r["state"] == "responded" for r in requests.get("requests", [])), requests)

    # 6. Refused: terms change between prepare and call.
    package_path = PRIVATE / "quote-2.json"
    fixture("quote", "--network-domain", str(WORK / "network-domain.json"), "--rpc", ",".join(rpc_endpoints()),
            "--registry-code-boc", str(REGISTRY_BOC), "--registry-code-hash", REGISTRY_CODE_HASH,
            "--code-hash", ACTOR_CODE_HASH, "--state-dir", str(PRIVATE / "provider-quote"), "--manifest", manifest["path"],
            "--capability-id", capability_id, "--provider-agent-id", agent_id, "--buyer-wallet", BUYER, "--out", str(package_path))
    stale = json.loads(buyer("prepare", "--package", str(package_path), "--execution-id", secrets.token_hex(32),
                             "--input-digest", secrets.token_hex(32)).stdout)
    before = service_show(actor)["next_request_id"]
    update_policy(actor, metadata["metadata_hash"], metadata["proof_scheme_hash"], "0.11")
    changed = poll(lambda: service_show(actor).get("terms_hash") != stale["terms_hash"], 180, 3)
    refused = None
    if changed:
        def attempt():
            result = buyer("call", "--request-hash", stale["request_hash"], *call_flags[2:], check=False)
            return result if "admission step 8" in result.stderr else None
        refused = poll(attempt, 180, 4)
    phase = json.loads((PRIVATE / "buyer" / "journal" / f"call-{stale['request_hash']}.json").read_text())["phase"]
    after = service_show(actor)["next_request_id"]
    record("a call prepared under terms the provider changed is refused before sending",
           bool(refused) and phase == "prepared" and after == before,
           {"stderr": refused.stderr.strip()[-400:] if refused else None, "phase": phase,
            "next_request_id_before": before, "next_request_id_after": after})


evidence: dict = {}


async def main() -> int:
    global GLOBAL_CONFIG, TOSCTL_SHA256
    from tostester.install import Install
    from tostester.n6_cluster import _wait_all_heights
    from tostester.network import Network, StartOptions, _write_model

    shutil.rmtree(WORK / "network", ignore_errors=True)
    for directory in (WORK, PRIVATE, WORK / "manifests"):
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700)
    for state in ("buyer", "wrong-code", "provider-quote"):
        (PRIVATE / state).mkdir(mode=0o700, exist_ok=True)
    # The launcher scans every artifact for this value after the run exits.
    secret_file = PRIVATE / "scan-secrets"
    secret_file.write_text(MASTER_KEY + "\n")
    secret_file.chmod(0o600)
    TOSCTL_SHA256 = hashlib.sha256(TOSCTL.read_bytes()).hexdigest()
    evidence.update({"schema": "tos.service.service-actor-buyer.local-acceptance.v1",
                     "qualifies_as_public_acceptance": False,
                     "reason": "one host runs every validator and endpoint",
                     "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                     "tos_source": str(SOURCE), "tos_build": str(BUILD),
                     "tosctl": {"path": str(TOSCTL), "sha256": TOSCTL_SHA256},
                     "protocol_commit": subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True,
                                                       text=True).stdout.strip(),
                     "actor_code_hash": ACTOR_CODE_HASH, "network_label": NETWORK_LABEL,
                     "stand_ins": {
                         "manifest_store": "local directory of canonical manifest CBOR files named by sha256 digest",
                         "quote_source": "service-actor-e2e-fixture quote: pkg/quoteprovider over finalized state, no gateway"}})
    try:
        async with Network(Install(BUILD, SOURCE), WORK / "network", base_port=BASE_PORT) as network:
            dht = network.create_dht_node()
            nodes = []
            for _ in range(len(RPC_PORTS)):
                node = network.create_full_node()
                node.announce_to(dht)
                node.make_initial_pq_validator(secrets.token_bytes(32), secrets.token_bytes(32))
                nodes.append(node)
            await dht.run(StartOptions(threads=1, verbosity=1))
            for node, port in zip(nodes, RPC_PORTS):
                await node.run(StartOptions(threads=2, verbosity=1, args=["--json-rpc-address", f"127.0.0.1:{port}"]))
            await _wait_all_heights(nodes, 5, 300)
            client = await nodes[0].toslib_client()
            global_config = json.loads((nodes[0].directory / "config.global.json").read_text())
            _write_model(WORK / "liteserver.json", nodes[0].liteserver_config)
            global_config["liteservers"] = json.loads((WORK / "liteserver.json").read_text())["liteservers"]
            GLOBAL_CONFIG = WORK / "global.json"
            GLOBAL_CONFIG.write_text(json.dumps(global_config, indent=2))
            zerostate = network.zerostate.as_block()
            domain = {"network_id": NETWORK_LABEL, "genesis_root_hash": "sha256:" + zerostate.root_hash.hex(),
                      "genesis_file_hash": "sha256:" + zerostate.file_hash.hex()}
            (WORK / "network-domain.json").write_text(json.dumps(domain))
            evidence["network"] = {**domain, "validators": len(nodes), "json_rpc": rpc_endpoints(), "base_port": BASE_PORT}
            ready = poll(lambda: "result" in rpc("getMasterchainInfo"), 180)
            record("every validator serves finalized JSON-RPC", bool(ready))
            await provision(network.zerostate.main_wallet(client))
            await asyncio.to_thread(acceptance)
    except Exception as error:  # noqa: BLE001 - the evidence records the failure
        record("run completed without an exception", False, repr(error))
    evidence["steps"] = steps
    evidence["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    passed = bool(steps) and all(step["pass"] for step in steps)
    evidence["result"] = "ALL PASS" if passed else "FAIL"
    (WORK / "evidence.json").write_text(json.dumps(redact_value(evidence), indent=2) + "\n")
    print(f"evidence: {WORK / 'evidence.json'}")
    print("ALL PASS" if passed else "FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
