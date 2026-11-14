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
                  "--tosctl-config", str(CONFIG), "--wallet", "buyer"]  # VAULT_URL comes from run()'s environment
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
    LIFE.update(actor=actor, capability_id=capability_id, agent_id=agent_id, manifest=manifest["path"],
                call_flags=call_flags, provider=provider)


# --- Settlement lifecycle (E2E_LIFECYCLE=1) ---------------------------------
#
# The contract fixes the minimum response SLA and refund-claim window at one
# hour each, so the expiry, refund and sweep success paths can only be shown by
# waiting them out. This phase does that with real calls, and also kills the
# buyer process mid-send to show the journal recovers without a second call.

LIFECYCLE = os.environ.get("E2E_LIFECYCLE") == "1"
LIFE: dict = {}
DEADLINE_MARGIN = 90


def nano_tos(text: str) -> int:
    from decimal import Decimal
    value = Decimal(str(text).split()[0]) * NANO
    if value != value.to_integral_value():
        raise ValueError(f"amount {text!r} is finer than one nanoTOS")
    return int(value)


def balance(address: str) -> int:
    return int(rpc("getAddressInformation", address=address)["result"]["balance"])


def revenue() -> int:
    return nano_tos(service_show(LIFE["actor"])["withdrawable_revenue"])


def quote_and_prepare(label: str) -> dict:
    package_path = PRIVATE / f"quote-{label}.json"
    fixture("quote", "--network-domain", str(WORK / "network-domain.json"), "--rpc", ",".join(rpc_endpoints()),
            "--registry-code-boc", str(REGISTRY_BOC), "--registry-code-hash", REGISTRY_CODE_HASH,
            "--code-hash", ACTOR_CODE_HASH, "--state-dir", str(PRIVATE / "provider-quote"), "--manifest", LIFE["manifest"],
            "--capability-id", LIFE["capability_id"], "--provider-agent-id", LIFE["agent_id"], "--buyer-wallet", BUYER,
            "--out", str(package_path))
    return json.loads(buyer("prepare", "--package", str(package_path), "--execution-id", secrets.token_hex(32),
                            "--input-digest", secrets.token_hex(32)).stdout)


def wait_state(request_hash: str, states: set, timeout: float = 300) -> dict:
    return poll(lambda: (lambda r: r if r.get("state") in states else None)(status_of(request_hash)), timeout, 5) or {}


def place_call(label: str) -> dict:
    prepared = quote_and_prepare(label)
    called = buyer("call", "--request-hash", prepared["request_hash"], *LIFE["call_flags"][2:], check=False)
    status = wait_state(prepared["request_hash"], {"pending"})
    record(f"request {label} is called and pending", called.returncode == 0 and bool(status),
           status or (called.stderr.strip()[-400:] + " " + str(LAST_STATUS_ERROR[0])))
    return {"request_hash": prepared["request_hash"], "payment": prepared.get("payment_nanotos"), **status}


def journal_phase(request_hash: str) -> str:
    return json.loads((PRIVATE / "buyer" / "journal" / f"call-{request_hash}.json").read_text())["phase"]


def find_sender(request_hash: str, exclude: int):
    """The pid of a live process whose command line carries request_hash."""
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == exclude:
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        if request_hash.encode() in cmdline and b"service" in cmdline:
            return int(entry.name)
    return None


def start_call(request_hash: str) -> subprocess.Popen:
    env = dict(os.environ)
    env["VAULT_URL"] = VAULT_URL
    return subprocess.Popen([str(BIN / "tos-service-buyer"), "call", *common_flags("buyer"), "--request-hash",
                             request_hash, *LIFE["call_flags"][2:]], env=env, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


def kill(process: subprocess.Popen) -> int:
    import signal
    if process.poll() is None:
        process.send_signal(signal.SIGKILL)
    return process.wait(timeout=30)


def next_request_id() -> int:
    return int(service_show(LIFE["actor"])["next_request_id"])


def crash_before_broadcast() -> None:
    """Kill the buyer as soon as its tosctl send starts, before the call can
    reach the chain. No request may appear, the record must stay quarantined as
    ambiguous, and the buyer must never send it again or lose funds."""
    import signal
    prepared = quote_and_prepare("crash-before")
    request_hash = prepared["request_hash"]
    before, wallet_before = next_request_id(), balance(BUYER)
    process = start_call(request_hash)
    sender = poll(lambda: find_sender(request_hash, process.pid), 60, 0.02)
    phase_at_kill = journal_phase(request_hash)
    exit_code = kill(process)
    record("crash before broadcast: the buyer was killed while its send was starting",
           sender is not None and exit_code == -signal.SIGKILL and phase_at_kill == "sending",
           {"sender_seen": sender is not None, "buyer_exit": exit_code, "phase_at_kill": phase_at_kill})
    poll(lambda: find_sender(request_hash, process.pid) is None, 120, 1)
    time.sleep(30)  # several blocks: a broadcast that did happen would be finalized by now
    created = next_request_id() - before
    report = status_of(request_hash)
    again = buyer("call", "--request-hash", request_hash, *LIFE["call_flags"][2:], check=False)
    detail = {"requests_created": created, "phase": journal_phase(request_hash), "status": report,
              "resend_stderr": again.stderr.strip()[-200:], "buyer_wallet_delta": balance(BUYER) - wallet_before}
    LIFE["evidence"]["crash_before_broadcast"] = detail
    if created == 1:
        # The send escaped before the kill took effect: then it must resolve
        # exactly like the after-broadcast case.
        record("crash before broadcast: an escaped send resolves to the one finalized call",
               report.get("state") == "pending" and again.returncode != 0, detail)
        return
    record("crash before broadcast: no request was created and the record stays quarantined as ambiguous",
           created == 0 and detail["phase"] == "ambiguous" and not report.get("found"), detail)
    record("crash before broadcast: the quarantined call is never sent again and costs the buyer nothing",
           again.returncode != 0 and "never sent again" in again.stderr and detail["buyer_wallet_delta"] == 0, detail)


def crash_after_broadcast() -> None:
    """Kill the buyer after its call is on chain but before it journals the
    outcome. The restarted journal must resolve that one call from finalized
    state, never send it again, and the request must then settle once."""
    import signal
    prepared = quote_and_prepare("crash-after")
    request_hash = prepared["request_hash"]
    before = next_request_id()
    process = start_call(request_hash)
    broadcast = poll(lambda: next_request_id() > before or None, 120, 0.2)
    still_waiting = process.poll() is None
    phase_at_kill = journal_phase(request_hash)
    exit_code = kill(process)
    record("crash after broadcast: the buyer was killed after its call reached the chain",
           bool(broadcast) and still_waiting and phase_at_kill == "sending" and exit_code == -signal.SIGKILL,
           {"call_on_chain": bool(broadcast), "buyer_still_waiting": still_waiting, "phase_at_kill": phase_at_kill,
            "buyer_exit": exit_code})
    # The killed buyer's tosctl keeps waiting for finality and holds the vault
    # until it exits; the provider's tosctl shares that vault in this run.
    orphan_gone = poll(lambda: find_sender(request_hash, process.pid) is None, 300, 1)
    status = wait_state(request_hash, {"pending"})
    phase_after = journal_phase(request_hash)
    again = buyer("call", "--request-hash", request_hash, *LIFE["call_flags"][2:], check=False)
    created = next_request_id() - before
    detail = {"phase": phase_after, "status": status or LAST_STATUS_ERROR[0], "requests_created": created,
              "resend_stderr": again.stderr.strip()[-200:], "orphaned_sender_exited": bool(orphan_gone)}
    LIFE["evidence"]["crash_after_broadcast"] = detail
    record("crash after broadcast: the restarted journal resolves the one finalized call",
           bool(status) and created == 1, detail)
    record("crash after broadcast: the call is never sent again", again.returncode != 0 and "never sent again" in again.stderr,
           detail)
    if not status:
        return
    response_hash = secrets.token_hex(32)
    tosctl("agent", "service", "send", "--operation", "respond", "--address", LIFE["actor"], "--from", "provider",
           "--request-id", str(status["request_id"]), "--response-hash", response_hash, "--attestor-controller",
           "service-attestor", "--yes")
    responded = wait_state(request_hash, {"responded"})
    record("crash after broadcast: the recovered request settles once by an attested respond",
           responded.get("response_hash") == response_hash and next_request_id() - before == 1,
           responded or LAST_STATUS_ERROR[0])


def withdraw() -> None:
    provider = LIFE["provider"]
    credited, wallet_before = revenue(), balance(provider)
    # tosctl shows revenue to 0.0001 TOS, so withdraw a multiple of that unit
    # to keep the before/after comparison exact.
    amount = (credited // 2) // 100_000 * 100_000
    tosctl("agent", "service", "send", "--operation", "withdraw-revenue", "--address", LIFE["actor"], "--from", "provider",
           "--withdraw-amount", f"{amount / NANO:.9f}", "--yes")
    decreased = poll(lambda: revenue() == credited - amount, 180, 3)
    wallet_after = balance(provider)
    received = wallet_after - wallet_before
    # The provider pays the payout message's network fees; everything else of
    # the 0.2 TOS allowance comes back as change.
    record("withdraw_revenue debits credited revenue by exactly the amount", bool(decreased),
           {"credited_before": credited, "amount": amount, "credited_after": revenue()})
    record("the provider wallet receives the withdrawal less only network fees", amount - NANO // 10 < received <= amount,
           {"amount": amount, "wallet_delta": received})
    LIFE["evidence"]["withdrawal"] = {"amount_nanotos": amount, "wallet_delta_nanotos": received}


def refund_path(request: dict) -> None:
    request_hash = request["request_hash"]
    view = service_show(LIFE["actor"])
    price = nano_tos(view["price_per_call"]) if "price_per_call" in view else None
    wait_until(request["response_deadline"] + DEADLINE_MARGIN, "the response deadline of the refund request")
    tosctl("agent", "service", "send", "--operation", "expire", "--address", LIFE["actor"], "--from", "provider",
           "--request-id", str(request["request_id"]), "--yes")
    expired = wait_state(request_hash, {"expired"})
    record("an unanswered request is expired after its response deadline", expired.get("status") == "refundable", expired)
    refund = tosctl_json("agent", "service", "refund-show", "--address", LIFE["actor"], "--request-id",
                         str(request["request_id"]))
    credited, wallet_before = revenue(), balance(BUYER)
    tosctl("agent", "service", "send", "--operation", "claim-refund", "--address", LIFE["actor"], "--from", "buyer",
           "--request-id", str(request["request_id"]), "--destination", BUYER, "--yes")
    refunded = wait_state(request_hash, {"refunded"})
    received = balance(BUYER) - wallet_before
    refund_price = nano_tos(refund.get("price", "0")) if refund.get("found") else price
    storage_fee = nano_tos(refund.get("storage_fee", "0")) if refund.get("found") else None
    record("the caller's claim_refund returns the price", bool(refunded) and refund_price is not None and
           refund_price - NANO // 10 < received <= refund_price,
           {"state": refunded.get("state"), "price": refund_price, "wallet_delta": received, "refund_entry": refund})
    record("the storage fee is not refunded and is credited to the provider", storage_fee is not None and
           revenue() - credited == storage_fee, {"revenue_delta": revenue() - credited, "storage_fee": storage_fee})
    LIFE["evidence"]["refund"] = {"request_id": request["request_id"], "price_nanotos": refund_price,
                                  "buyer_wallet_delta_nanotos": received, "storage_fee_nanotos": storage_fee}


def sweep_path(request: dict) -> None:
    request_hash = request["request_hash"]
    snapshot = tosctl_json("agent", "service", "request-show", "--address", LIFE["actor"], "--request-id",
                           str(request["request_id"]))
    price, storage_fee, bounty = (nano_tos(snapshot[k]) for k in ("price", "storage_fee", "cleanup_bounty"))
    wait_until(request["refund_claim_deadline"] + DEADLINE_MARGIN, "the refund-claim deadline of the sweep request")
    credited, buyer_before, provider_before = revenue(), balance(BUYER), balance(LIFE["provider"])
    tosctl("agent", "service", "send", "--operation", "sweep-expired-request", "--address", LIFE["actor"], "--from",
           "provider", "--request-id", str(request["request_id"]), "--yes")
    swept = wait_state(request_hash, {"swept"})
    buyer_delta, revenue_delta = balance(BUYER) - buyer_before, revenue() - credited
    provider_delta = balance(LIFE["provider"]) - provider_before
    record("a never-expired request is swept after its refund-claim deadline", swept.get("state") == "swept", swept)
    record("the sweep returns exactly the price to the caller", buyer_delta == price,
           {"price": price, "buyer_wallet_delta": buyer_delta})
    record("the provider is credited the storage fee less the cleanup bounty", revenue_delta == storage_fee - bounty,
           {"storage_fee": storage_fee, "cleanup_bounty": bounty, "revenue_delta": revenue_delta})
    record("the sweeper receives the bounty less only network fees", bounty - NANO // 10 < provider_delta <= bounty,
           {"cleanup_bounty": bounty, "sweeper_wallet_delta": provider_delta})
    LIFE["evidence"]["sweep"] = {"request_id": request["request_id"], "price_nanotos": price,
                                 "storage_fee_nanotos": storage_fee, "cleanup_bounty_nanotos": bounty,
                                 "buyer_wallet_delta_nanotos": buyer_delta, "revenue_delta_nanotos": revenue_delta,
                                 "sweeper_wallet_delta_nanotos": provider_delta}


def wait_until(unix_seconds: int, what: str) -> None:
    remaining = int(unix_seconds) - int(time.time())
    print(f"waiting {max(remaining, 0)} s for {what}", flush=True)
    while time.time() < unix_seconds:
        time.sleep(min(60, max(1, unix_seconds - time.time())))


def lifecycle() -> None:
    if "actor" not in LIFE:
        record("settlement lifecycle prerequisites are present", False, "acceptance did not complete")
        return
    LIFE["evidence"] = evidence.setdefault("lifecycle", {})
    crash_before_broadcast()
    crash_after_broadcast()
    withdraw()
    refund_request = place_call("refund")
    sweep_request = place_call("sweep")
    LIFE["evidence"]["requests"] = {"refund": refund_request.get("request_id"), "sweep": sweep_request.get("request_id")}
    # Each path is recorded on its own, so a failure in one still lets the
    # other's hour-long wait produce evidence.
    for name, path, request, key in (("refund", refund_path, refund_request, "response_deadline"),
                                     ("sweep", sweep_path, sweep_request, "refund_claim_deadline")):
        if not request.get(key):
            record(f"{name} path has a pending request to settle", False, request)
            continue
        try:
            path(request)
        except Exception as error:  # noqa: BLE001 - the evidence records the failure
            record(f"{name} path completed without an exception", False, repr(error))


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
            if LIFECYCLE:
                await asyncio.to_thread(lifecycle)
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
