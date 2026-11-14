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

E2E_EXECUTE=1 adds paid execution: the buyer calls with a real source
archive, the provider runs `software-work-execute paid` in the private
containerd sandbox, the attestor checks and signs the Receipt hash, and the
buyer resolves exactly that response. E2E_LIFECYCLE=1 adds the settlement
lifecycle (about two hours of deadlines).

Stand-ins, both local and authority-free: the manifest store is a directory
of canonical CBOR files named by digest, and the Quote Proposal comes from
`service-actor-e2e-fixture quote`, which runs pkg/quoteprovider against
finalized state instead of a provider gateway.

Run it through scripts/service-actor-buyer-e2e.sh, which places the network
in its own process group under the thermal guard. The run ends with an
evidence file and one ALL PASS or FAIL line.
"""

import asyncio
import base64
import datetime
import hashlib
import io
import json
import os
import secrets
import shutil
import subprocess
import sys
import tarfile
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
    # Only the paid execution phase publishes the executor's image and
    # invocation; without it the manifest is the fixture's own.
    executor_manifest = ["--toolchain-digest", EXECUTOR_IMAGE, "--invocation-args", EXECUTOR_ARGUMENTS] if EXECUTE else []
    manifest = fixture("manifest", "--actor", actor, "--code-hash", ACTOR_CODE_HASH, "--attestor", attestor_text,
                       "--version", "1.0.0", "--out-dir", str(WORK / "manifests"), *executor_manifest)
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
                manifest_digest=digest, attestor=attestor_text, call_flags=call_flags, provider=provider)


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


def quote_and_prepare(label: str, execution_id: str | None = None, input_digest: str | None = None) -> dict:
    package_path = PRIVATE / f"quote-{label}.json"
    fixture("quote", "--network-domain", str(WORK / "network-domain.json"), "--rpc", ",".join(rpc_endpoints()),
            "--registry-code-boc", str(REGISTRY_BOC), "--registry-code-hash", REGISTRY_CODE_HASH,
            "--code-hash", ACTOR_CODE_HASH, "--state-dir", str(PRIVATE / "provider-quote"), "--manifest", LIFE["manifest"],
            "--capability-id", LIFE["capability_id"], "--provider-agent-id", LIFE["agent_id"], "--buyer-wallet", BUYER,
            "--out", str(package_path))
    return json.loads(buyer("prepare", "--package", str(package_path), "--execution-id", execution_id or secrets.token_hex(32),
                            "--input-digest", input_digest or secrets.token_hex(32)).stdout)


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


def start_call(request_hash: str, new_session: bool = False) -> subprocess.Popen:
    env = dict(os.environ)
    env["VAULT_URL"] = VAULT_URL
    return subprocess.Popen([str(BIN / "tos-service-buyer"), "call", *common_flags("buyer"), "--request-hash",
                             request_hash, *LIFE["call_flags"][2:]], env=env, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, start_new_session=new_session)


def kill(process: subprocess.Popen) -> int:
    import signal
    if process.poll() is None:
        process.send_signal(signal.SIGKILL)
    return process.wait(timeout=30)


def next_request_id() -> int:
    return int(service_show(LIFE["actor"])["next_request_id"])


def crash_before_broadcast() -> None:
    """Kill the buyer and its custody child as soon as the send starts, so
    nothing can reach the chain. No request may appear, the record must stay
    quarantined as ambiguous, and the buyer must never send it again or lose
    funds."""
    import signal
    prepared = quote_and_prepare("crash-before")
    request_hash = prepared["request_hash"]
    before, wallet_before = next_request_id(), balance(BUYER)
    # Its own session, so one signal reaches the buyer and the tosctl it
    # starts: the buyer is the group leader.
    process = start_call(request_hash, new_session=True)
    sender = poll(lambda: find_sender(request_hash, process.pid), 60, 0.02)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    exit_code = process.wait(timeout=30)
    sender_gone = poll(lambda: find_sender(request_hash, process.pid) is None, 30, 0.2)
    phase_at_kill = journal_phase(request_hash)
    record("crash before broadcast: the buyer and its sender were killed while the send was starting",
           sender is not None and exit_code == -signal.SIGKILL and bool(sender_gone) and phase_at_kill == "sending",
           {"sender_seen": sender is not None, "buyer_exit": exit_code, "sender_gone": bool(sender_gone),
            "phase_at_kill": phase_at_kill})
    time.sleep(30)  # several blocks: a broadcast that did happen would be finalized by now
    created = next_request_id() - before
    report = status_of(request_hash)
    again = buyer("call", "--request-hash", request_hash, *LIFE["call_flags"][2:], check=False)
    detail = {"requests_created": created, "phase": journal_phase(request_hash), "status": report,
              "resend_stderr": again.stderr.strip()[-200:], "buyer_wallet_delta": balance(BUYER) - wallet_before}
    LIFE["evidence"]["crash_before_broadcast"] = detail
    record("crash before broadcast: no request was created and the record stays quarantined as ambiguous",
           created == 0 and detail["phase"] == "ambiguous" and not report.get("found"), detail)
    record("crash before broadcast: the quarantined call is never sent again and costs the buyer nothing",
           again.returncode != 0 and "never sent again" in again.stderr and detail["buyer_wallet_delta"] == 0, detail)


def crash_after_broadcast() -> None:
    """Kill the buyer after its call is on chain but before it journals the
    outcome. Only the buyer dies: its custody child finishes on its own. The
    restarted journal must resolve that one call from finalized state, never
    send it again, and the request must then settle once."""
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
    record("crash after broadcast: the orphaned sender exited and the restarted journal resolved the one call as admitted",
           bool(orphan_gone) and bool(status) and created == 1 and phase_after == "admitted", detail)
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
    credited = revenue()
    # tosctl shows revenue to 0.0001 TOS, so withdraw a multiple of that unit
    # to keep the before/after comparison exact.
    amount = (credited // 2) // 100_000 * 100_000
    record("there is credited revenue to withdraw", amount > 0, {"credited": credited, "amount": amount})
    if amount <= 0:
        return
    settled = actor_settlement(provider, lambda: tosctl(
        "agent", "service", "send", "--operation", "withdraw-revenue", "--address", LIFE["actor"], "--from", "provider",
        "--withdraw-amount", f"{amount / NANO:.9f}", "--yes"), [provider])
    decreased = poll(lambda: revenue() == credited - amount, 180, 3)
    record("withdraw_revenue debits credited revenue by exactly the amount", bool(decreased),
           {"credited_before": credited, "amount": amount, "credited_after": revenue()})
    payouts, flow = settled.get("payouts") or [], settled.get(provider) or {}
    # pay_with_change: exactly the amount to the owner, then the change.
    record("the withdrawal pays exactly the amount, then the change, to the provider",
           len(payouts) == 2 and payouts[0]["destination"] == provider and payouts[0]["value"] == amount and
           payouts[1]["destination"] == provider, {"amount": amount, "payouts": payouts, "error": settled.get("error")})
    record("the provider wallet moves by exactly its inbound payouts less its send and its own fees", flow.get("exact") is True,
           flow)
    LIFE["evidence"]["withdrawal"] = {"amount_nanotos": amount, "settlement": settled}


def refund_path(request: dict) -> None:
    request_hash = request["request_hash"]
    snapshot = tosctl_json("agent", "service", "request-show", "--address", LIFE["actor"], "--request-id",
                           str(request["request_id"]))
    price = nano_tos(snapshot["price"])
    wait_until(request["response_deadline"] + DEADLINE_MARGIN, "the response deadline of the refund request")
    tosctl("agent", "service", "send", "--operation", "expire", "--address", LIFE["actor"], "--from", "provider",
           "--request-id", str(request["request_id"]), "--yes")
    expired = wait_state(request_hash, {"expired"})
    record("an unanswered request is expired after its response deadline", expired.get("status") == "refundable", expired)
    refund = tosctl_json("agent", "service", "refund-show", "--address", LIFE["actor"], "--request-id",
                         str(request["request_id"]))
    complete = refund.get("found") is True and all(key in refund for key in ("price", "storage_fee"))
    record("the refund entry exists with its price and storage fee", complete and nano_tos(refund["price"]) == price,
           {"refund_entry": refund, "snapshot_price": price})
    if not complete:
        return
    storage_fee = nano_tos(refund["storage_fee"])
    credited = revenue()
    settled = actor_settlement(BUYER, lambda: tosctl(
        "agent", "service", "send", "--operation", "claim-refund", "--address", LIFE["actor"], "--from", "buyer",
        "--request-id", str(request["request_id"]), "--destination", BUYER, "--yes"), [BUYER])
    refunded = wait_state(request_hash, {"refunded"})
    payouts, flow = settled.get("payouts") or [], settled.get(BUYER) or {}
    record("claim_refund pays exactly the snapshotted price to the destination, then the change",
           bool(refunded) and len(payouts) == 2 and payouts[0]["destination"] == BUYER and payouts[0]["value"] == price and
           payouts[1]["destination"] == BUYER, {"state": refunded.get("state"), "price": price, "payouts": payouts,
                                                 "error": settled.get("error")})
    record("the caller's wallet moves by exactly the payouts less its claim and its own fees", flow.get("exact") is True, flow)
    record("the storage fee is not refunded and is credited to the provider", revenue() - credited == storage_fee,
           {"revenue_delta": revenue() - credited, "storage_fee": storage_fee})
    LIFE["evidence"]["refund"] = {"request_id": request["request_id"], "price_nanotos": price,
                                  "storage_fee_nanotos": storage_fee, "settlement": settled}


def sweep_path(request: dict) -> None:
    request_hash, provider = request["request_hash"], LIFE["provider"]
    snapshot = tosctl_json("agent", "service", "request-show", "--address", LIFE["actor"], "--request-id",
                           str(request["request_id"]))
    price, storage_fee, bounty = (nano_tos(snapshot[k]) for k in ("price", "storage_fee", "cleanup_bounty"))
    wait_until(request["refund_claim_deadline"] + DEADLINE_MARGIN, "the refund-claim deadline of the sweep request")
    credited = revenue()
    settled = actor_settlement(provider, lambda: tosctl(
        "agent", "service", "send", "--operation", "sweep-expired-request", "--address", LIFE["actor"], "--from",
        "provider", "--request-id", str(request["request_id"]), "--yes"), [BUYER, provider])
    swept = wait_state(request_hash, {"swept"})
    revenue_delta = revenue() - credited
    record("a never-expired request is swept after its refund-claim deadline", swept.get("state") == "swept", swept)
    payouts = settled.get("payouts") or []
    caller, sweeper = settled.get(BUYER) or {}, settled.get(provider) or {}
    # The actor's obligations are the messages it sends: exactly the price to
    # the caller, exactly the bounty to the sweeper, then the sweeper's change.
    record("the sweep sends exactly the price to the caller and exactly the bounty, then the change, to the sweeper",
           len(payouts) == 3 and payouts[0]["destination"] == BUYER and payouts[0]["value"] == price and
           payouts[1]["destination"] == provider and payouts[1]["value"] == bounty and payouts[2]["destination"] == provider,
           {"price": price, "cleanup_bounty": bounty, "payouts": payouts, "error": settled.get("error")})
    # Each balance is measured once its payouts have arrived and reconciled
    # exactly: inbound values less outbound values and forwarding fees less
    # the account's own transaction fees.
    record("the caller's balance moves by exactly the price less only its own account fees",
           caller.get("exact") is True and caller.get("outbound") == 0 and caller.get("inbound") == price, caller)
    record("the sweeper's balance moves by exactly its payouts less its send and its own fees", sweeper.get("exact") is True,
           sweeper)
    record("the provider is credited the storage fee less the cleanup bounty", revenue_delta == storage_fee - bounty,
           {"storage_fee": storage_fee, "cleanup_bounty": bounty, "revenue_delta": revenue_delta})
    LIFE["evidence"]["sweep"] = {"request_id": request["request_id"], "price_nanotos": price,
                                 "storage_fee_nanotos": storage_fee, "cleanup_bounty_nanotos": bounty,
                                 "revenue_delta_nanotos": revenue_delta, "settlement": settled}


def last_lt(address: str) -> int:
    rows = rpc("getTransactions", address=address, limit=1)["result"]
    return int(rows[0]["transaction_id"]["lt"]) if rows else 0


def transactions_after(address: str, baseline_lt: int) -> list:
    rows = rpc("getTransactions", address=address, limit=10)["result"]
    if len(rows) == 10 and all(int(row["transaction_id"]["lt"]) > baseline_lt for row in rows):
        raise RuntimeError("the transaction page did not reach the baseline")
    return [row for row in rows if int(row["transaction_id"]["lt"]) > baseline_lt]


# --- Exact settlement accounting --------------------------------------------
#
# A payout is checked as the message the actor sends, and a wallet's balance
# as an exact identity over the transactions between two state reads:
# delta = inbound message values - (outbound values + forwarding and IHR fees)
#         - the account's total transaction fees.
# Every value comes from the decoded transaction cells, not the RPC summary.

def account_state(address: str) -> tuple[int, int]:
    """Balance and last transaction lt from one account state read."""
    info = rpc("getAddressInformation", address=address)["result"]
    return int(info["balance"]), int(info["last_transaction_id"]["lt"])


def raw_address(address) -> str:
    return address.to_str(is_user_friendly=False).lower()


def transaction_summary(row: dict) -> dict:
    from pytosiq_core import Cell, Transaction
    transaction = Transaction.deserialize(Cell.one_from_boc(base64.b64decode(row["data"])).begin_parse())
    inbound = transaction.in_msg.info if transaction.in_msg is not None and transaction.in_msg.is_internal else None
    return {"lt": int(row["transaction_id"]["lt"]), "hash": row["transaction_id"]["hash"],
            "in_source": raw_address(inbound.src) if inbound else None, "in_value": inbound.value_coins if inbound else 0,
            "in_created_lt": inbound.created_lt if inbound else None,
            "outs": [{"destination": raw_address(m.info.dest), "value": m.info.value_coins, "fwd_fee": m.info.fwd_fee,
                      "ihr_fee": m.info.ihr_fee, "created_lt": m.info.created_lt}
                     for m in transaction.out_msgs if m.is_internal],
            "total_fees": transaction.total_fees.tomis, "aborted": bool(row.get("aborted")),
            "compute_success": (row.get("compute") or {}).get("success")}


def account_flow(address: str, before: tuple[int, int], settled, timeout: float = 240) -> dict:
    """Wait until settled(transactions since before) holds, then reconcile the
    balance change exactly against those transactions."""
    def attempt():
        balance_after, lt_after = account_state(address)
        rows = [transaction_summary(row) for row in transactions_after(address, before[1])
                if int(row["transaction_id"]["lt"]) <= lt_after]
        if max((row["lt"] for row in rows), default=before[1]) != lt_after or not settled(rows):
            return None
        return {"balance_after": balance_after, "transactions": rows}
    seen = poll(attempt, timeout, 3)
    if not seen:
        return {"exact": False, "error": "the expected transactions never arrived"}
    rows = seen["transactions"]
    inbound = sum(row["in_value"] for row in rows)
    outbound = sum(out["value"] for row in rows for out in row["outs"])
    forwarding = sum(out["fwd_fee"] + out["ihr_fee"] for row in rows for out in row["outs"])
    fees = sum(row["total_fees"] for row in rows)
    delta = seen["balance_after"] - before[0]
    return {"delta": delta, "inbound": inbound, "outbound": outbound, "forwarding_fees": forwarding, "fees": fees,
            "exact": delta == inbound - outbound - forwarding - fees, "transactions": rows}


def actor_settlement(sender: str, send, wallets: list[str], timeout: float = 240) -> dict:
    """Run send, find the one actor transaction that processed the sender's
    message, list its internal payouts in order, and reconcile each wallet
    once every payout to it has arrived."""
    actor = LIFE["actor"]
    actor_before = last_lt(actor)
    befores = {wallet: account_state(wallet) for wallet in wallets}
    send()

    def processed():
        rows = [transaction_summary(row) for row in transactions_after(actor, actor_before)]
        return [row for row in rows if row["in_source"] == sender] or None
    mine = poll(processed, timeout, 3) or []
    result: dict = {"actor_transactions": mine}
    if len(mine) != 1 or mine[0]["aborted"] or not mine[0]["compute_success"]:
        result["error"] = "expected exactly one successful actor transaction from the sender"
        return result
    payouts = mine[0]["outs"]
    result["payouts"] = payouts
    for wallet in wallets:
        expected = {out["created_lt"] for out in payouts if out["destination"] == wallet}
        result[wallet] = account_flow(wallet, befores[wallet], lambda rows, e=expected: e <= {
            row["in_created_lt"] for row in rows if row["in_source"] == actor}, timeout)
    return result


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


# --- Paid execution (E2E_EXECUTE=1) -----------------------------------------
#
# The provider executes the paid software-work job for real: the buyer calls
# with a source archive, `software-work-execute paid` admits the finalized
# pending request at most once and runs it in the private containerd sandbox,
# and the attestor signs the resulting Receipt hash only after checking that
# the Receipt binds exactly this request. The executor needs root for the
# private containerd socket, so it alone runs under `sudo -n`, with every
# input staged root-owned and private.

EXECUTE = os.environ.get("E2E_EXECUTE") == "1"
EXECUTOR = Path(os.environ.get("E2E_EXECUTOR") or "/nonexistent")
TOS_AI_COMMIT = os.environ.get("E2E_TOS_AI_COMMIT", "")
# The executor's pinned toolchain image and invocation; the manifest must
# name exactly these or `paid` refuses the offer.
EXECUTOR_IMAGE = "sha256:9624bca74096f810c5b24e489521dde124fadcfa1808581648b38bdc1ba1b105"
EXECUTOR_ARGUMENTS = "test ./... -count=1"
CONTAINERD_SOCKET = "/run/tos-service-containerd/containerd.sock"
# The input digest is the transport's commitment to the source archive. This
# run is its own direct transport: SHA-256 over a domain prefix, a zero byte
# and the raw SHA-256 of the exact archive bytes.
INPUT_DOMAIN = b"tos.service.e2e.software-work-input.v1\x00"
EXIT_COMPLETED, EXIT_ALREADY_TAKEN, EXIT_NOT_ADMITTED, EXIT_EXECUTION_FAILED = 0, 3, 6, 7
EXEC: dict = {}


def sudo(*args, check: bool = True, timeout: int = 120) -> subprocess.CompletedProcess:
    """A root command; the vault URL is not passed to it."""
    return run_logged(["sudo", "-n", *map(str, args)], TRANSCRIPT, env=dict(os.environ), check=check, timeout=timeout)


def source_archive(passing: bool) -> bytes:
    """A deterministic USTAR archive of a Go module with one test."""
    check = "if 2+2 != 4 {\n\t\tt.Fatal(\"arithmetic\")\n\t}" if passing else "t.Fatal(\"this test fails on purpose\")"
    files = [("go.mod", "module example.test/paidwork\n\ngo 1.26.5\n"),
             ("work_test.go", f"package paidwork\n\nimport \"testing\"\n\nfunc TestWork(t *testing.T) {{\n\t{check}\n}}\n")]
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, body in files:
            data = body.encode()
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime, info.uid, info.gid, info.uname, info.gname = len(data), 0o444, 0, 0, 0, "", ""
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def input_digest_for(archive: bytes) -> str:
    return hashlib.sha256(INPUT_DOMAIN + hashlib.sha256(archive).digest()).hexdigest()


def install_root(source: Path, target: Path, mode: str = "0600") -> None:
    sudo("install", "-o", "root", "-g", "root", "-m", mode, source, target)


def stage_provider_root() -> None:
    """Root-owned private state outside the invoking user's work directory,
    so the user cannot swap a staged file: the executor binary, rail config,
    registry code, manifest, the persistent paid state directory and an
    inbox per request."""
    base = Path(os.environ.get("E2E_ROOT_BASE", "/tos/m1-e2e-root"))
    root = base / WORK.name
    EXEC.update(root=root, binary=root / "bin" / "software-work-execute", state=root / "paid", inbox=root / "inbox",
                rail=root / "etc" / "rail.json", fifo=Path("/run/tos-service-containerd") / f"e2e-{WORK.name}-fifos")
    sudo("install", "-d", "-o", "root", "-g", "root", "-m", "0700", base)
    if sudo("test", "-e", root, check=False).returncode == 0:
        raise RuntimeError(f"{root} already exists; every run stages a fresh provider root")
    sudo("install", "-d", "-o", "root", "-g", "root", "-m", "0700", root, root / "bin", root / "etc", EXEC["state"],
         EXEC["inbox"], EXEC["fifo"])
    EXEC["executor_sha256"] = hashlib.sha256(EXECUTOR.read_bytes()).hexdigest()
    install_root(EXECUTOR, EXEC["binary"], "0755")
    install_root(REGISTRY_BOC, root / "etc" / "registry-code.boc")
    install_root(Path(LIFE["manifest"]), root / "etc" / "manifest.cbor")
    domain = json.loads((WORK / "network-domain.json").read_text())
    rail = {"schema": "tos.ai.railgate-config.v1", "network": domain, "rpc_endpoints": rpc_endpoints(), "quorum": 0,
            "registry_code_boc_file": str(root / "etc" / "registry-code.boc"), "registry_code_hash": REGISTRY_CODE_HASH,
            "actor_code_hash": ACTOR_CODE_HASH, "provider_agent_id": LIFE["agent_id"],
            "capability_id": LIFE["capability_id"], "version": "1.0.0",
            "manifest_file": str(root / "etc" / "manifest.cbor"), "respond_budget_seconds": 120}
    staged = PRIVATE / "rail.json"
    staged.write_text(json.dumps(rail, indent=2))
    install_root(staged, EXEC["rail"])
    ownership = sudo("stat", "-c", "%U:%G %a %n", base, root, root / "bin", EXEC["binary"], EXEC["rail"]).stdout.split("\n")
    staged_sha = staged_executor_sha256()
    EXEC["evidence"].update(executor={"built": str(EXECUTOR), "sha256": EXEC["executor_sha256"], "staged_sha256": staged_sha,
                                      "tos_ai_commit": TOS_AI_COMMIT,
                                      "tos_ai_commit_source": "operator-asserted (E2E_TOS_AI_COMMIT), not derived from the binary"},
                            provider_root=str(root), provider_root_ownership=[line for line in ownership if line],
                            image_digest=EXECUTOR_IMAGE, invocation=EXECUTOR_ARGUMENTS,
                            manifest_digest=LIFE["manifest_digest"], rail_config=rail,
                            input_digest_domain=INPUT_DOMAIN.rstrip(b"\x00").decode())
    expected_modes = ["root:root 700", "root:root 700", "root:root 700", "root:root 755", "root:root 600"]
    owned = [line.rsplit(" ", 1)[0] for line in ownership if line] == expected_modes
    record("the provider staged the executor, rail config and manifest root-owned and private outside the work directory",
           staged_sha == EXEC["executor_sha256"] and owned and not str(root).startswith(str(WORK)),
           {"executor": EXEC["evidence"]["executor"], "provider_root": str(root), "ownership": ownership})


def staged_executor_sha256() -> str:
    return sudo("sha256sum", EXEC["binary"]).stdout.split()[0]


def call_with_source(label: str, archive: bytes) -> dict:
    """The buyer prepares and calls with the archive's input digest; returns
    what the buyer delivers to the provider for this request."""
    execution_id, input_digest = secrets.token_hex(32), input_digest_for(archive)
    prepared = quote_and_prepare(label, execution_id, input_digest)
    called: list = []
    settled = actor_settlement(BUYER, lambda: called.append(
        buyer("call", "--request-hash", prepared["request_hash"], *LIFE["call_flags"][2:], check=False)), [BUYER])
    status = wait_state(prepared["request_hash"], {"pending"})
    record(f"{label}: the buyer called with the source's input digest and the request is pending",
           called[0].returncode == 0 and bool(status) and bool(status.get("call_transaction")),
           status or (called[0].stderr.strip()[-400:] + " " + str(LAST_STATUS_ERROR[0])))
    # The exact-accounting instrument is shown to speak on a short run: the
    # call's payment leaves the wallet, the change returns, and the balance
    # reconciles to the nanoTOS.
    flow, sent = settled.get(BUYER) or {}, [out for row in (settled.get(BUYER) or {}).get("transactions", [])
                                            for out in row["outs"] if out["destination"] == LIFE["actor"]]
    record(f"{label}: the buyer wallet pays exactly the call payment and reconciles exactly",
           flow.get("exact") is True and len(sent) == 1 and str(sent[0]["value"]) == str(prepared["payment_nanotos"]),
           {"payment_nanotos": prepared["payment_nanotos"], "settlement": settled})
    journal = json.loads((PRIVATE / "buyer" / "journal" / f"call-{prepared['request_hash']}.json").read_text())
    return {"label": label, "archive": archive, "execution_id": execution_id, "input_digest": input_digest,
            "request_hash": prepared["request_hash"], "package": base64.b64decode(journal["package_base64"]),
            "status": status}


def deliver(task: dict) -> Path:
    """The transport stand-in: the provider receives the archive and the
    accepted Quote package, checks the archive against the committed input
    digest, and stages both privately for the executor."""
    local = PRIVATE / "provider-inbox" / task["label"]
    local.mkdir(mode=0o700, parents=True, exist_ok=True)
    (local / "source.tar").write_bytes(task["archive"])
    (local / "quote.pb").write_bytes(task["package"])
    task["package_path"] = local / "quote.pb"
    inbox = EXEC["inbox"] / task["label"]
    sudo("install", "-d", "-o", "root", "-g", "root", "-m", "0700", inbox)
    install_root(local / "source.tar", inbox / "source.tar")
    install_root(local / "quote.pb", inbox / "quote.pb")
    staged = sudo("sha256sum", inbox / "source.tar").stdout.split()[0]
    task["source_digest"] = "sha256:" + staged
    record(f"{task['label']}: the staged archive is the one the request's input digest commits",
           hashlib.sha256(INPUT_DOMAIN + bytes.fromhex(staged)).hexdigest() == task["input_digest"],
           {"source_digest": task["source_digest"], "input_digest": task["input_digest"]})
    return inbox


def paid(task: dict, inbox: Path) -> tuple[int, dict]:
    # The binary run as root is the one whose digest the evidence records.
    staged = staged_executor_sha256()
    if staged != EXEC["executor_sha256"]:
        raise RuntimeError(f"the staged executor changed: {staged} is not {EXEC['executor_sha256']}")
    status = task["status"]
    result = sudo(EXEC["binary"], "paid", "--rail-config", EXEC["rail"], "--containerd-socket", CONTAINERD_SOCKET,
                  "--fifo-dir", EXEC["fifo"], "--state-dir", EXEC["state"], "--source", inbox / "source.tar",
                  "--quote-package", inbox / "quote.pb", "--buyer-wallet", BUYER, "--actor", LIFE["actor"],
                  "--request-id", status["request_id"], "--call-lt", status["call_transaction"]["lt"],
                  "--call-hash", status["call_transaction"]["hash"], "--execution-id", "sha256:" + task["execution_id"],
                  "--input-digest", "sha256:" + task["input_digest"], check=False, timeout=900)
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        report = {"unparsed_stdout": result.stdout[-2000:], "stderr": result.stderr[-2000:]}
    return result.returncode, report


def slot_state_digest() -> dict:
    """A digest of the paid slots and job journal: every entry's path, type,
    size and mode, listed as root and sorted."""
    listing = sudo("find", EXEC["state"] / "slots", EXEC["state"] / "journal", "-mindepth", "1", "-printf",
                   "%P\t%y\t%s\t%m\n").stdout.splitlines()
    entries = sorted(listing)
    return {"entries": len(entries), "sha256": hashlib.sha256("\n".join(entries).encode()).hexdigest()}


def stored_digest(digest: str) -> str | None:
    path = EXEC["state"] / "artifacts" / "objects" / digest.removeprefix("sha256:")
    result = sudo("sha256sum", path, check=False)
    return "sha256:" + result.stdout.split()[0] if result.returncode == 0 else None


def request_snapshot(request_id: int) -> dict:
    return tosctl_json("agent", "service", "request-show", "--address", LIFE["actor"], "--request-id", str(request_id))


def attestor_check(task: dict, report: dict, snapshot: dict) -> tuple[bool, dict]:
    """The attestor releases the Receipt only if it binds the request the
    finalized snapshot names: the Accepted Quote rebuilt from the accepted
    package, with the claimed execution ID and input digest, must reproduce
    the snapshot's request hash."""
    checked = run([str(BIN / "service-actor-e2e-fixture"), "receipt-check",
                   "--receipt-boc", report["receipt_boc_base64"], "--response-hash", report["response_hash"],
                   "--quote-package", str(task["package_path"]), "--network-domain", str(WORK / "network-domain.json"),
                   "--execution-id", "sha256:" + task["execution_id"], "--input-digest", "sha256:" + task["input_digest"],
                   "--source-digest", task["source_digest"],
                   "--snapshot-request-hash", snapshot["request_hash"], "--snapshot-terms-hash", snapshot["terms_hash"],
                   "--snapshot-price-nanotos", str(nano_tos(snapshot["price"])),
                   "--snapshot-attestor-key", snapshot["attestor_key_id"], "--snapshot-caller", norm(snapshot["caller"]),
                   "--capability-id", LIFE["capability_id"], "--version", "1.0.0", "--buyer-wallet", BUYER,
                   "--actor", LIFE["actor"], "--attestor", LIFE["attestor"], "--provider-agent-id", LIFE["agent_id"],
                   "--toolchain-digest", EXECUTOR_IMAGE, "--manifest-digest", LIFE["manifest_digest"]], check=False)
    receipt = last_json(checked.stdout) or {}
    return checked.returncode == 0 and receipt.get("releasable") is True, receipt or {"error": checked.stderr.strip()[-600:]}


def execute_passing() -> None:
    task = call_with_source("paid-pass", source_archive(passing=True))
    if not task["status"]:
        return
    inbox = deliver(task)
    request_id = task["status"]["request_id"]
    snapshot = request_snapshot(request_id)
    EXEC["evidence"]["request_snapshot"] = snapshot
    code, report = paid(task, inbox)
    outcome = report.get("outcome") or {}
    response_hash = report.get("response_hash", "")
    run_evidence = {"request_id": request_id, "request_hash": task["request_hash"], "exit_code": code,
                    "status": report.get("status"), "slot_state": report.get("slot_state"),
                    "respond_check": report.get("respond_check"), "response_hash": response_hash,
                    "receipt_boc_base64": report.get("receipt_boc_base64"), "retain_until_unix": report.get("retain_until_unix"),
                    "quote_commitment": report.get("quote_commitment"), "outcome": outcome, "error": report.get("error")}
    EXEC["evidence"]["completed"] = run_evidence
    record("paid: the provider executed the request once in the sandbox and recorded its Receipt hash",
           code == EXIT_COMPLETED and report.get("status") == "completed" and report.get("respond_check") == "passed" and
           len(response_hash) == 64 and outcome.get("exit_code") == 0, run_evidence)
    if code != EXIT_COMPLETED:
        return
    # Negative control while the request is still pending, the only time a
    # second execution could happen: the slot refuses it and the slot and
    # journal entries stay exactly as they were.
    slots_before = slot_state_digest()
    again_code, again = paid(task, inbox)
    slots_after = slot_state_digest()
    EXEC["evidence"]["rerun_pending"] = {"exit_code": again_code, "report": again, "slots_before": slots_before,
                                         "slots_after": slots_after}
    record("paid again while the request is pending: already taken, not executed again, slots and journal unchanged",
           again_code == EXIT_ALREADY_TAKEN and again.get("status") == "already_taken" and not again.get("response_hash") and
           not again.get("outcome") and not again.get("receipt_boc_base64") and slots_before == slots_after and
           slots_before["entries"] > 0, EXEC["evidence"]["rerun_pending"])
    artifact, report_object = (outcome.get(key, {}).get("Digest", "") for key in ("artifact", "report"))
    stored = {"artifact": stored_digest(artifact), "report": stored_digest(report_object)}
    record("paid: the artifact and report are stored intact before respond",
           stored == {"artifact": artifact, "report": report_object}, stored)
    releasable, receipt = attestor_check(task, report, snapshot)
    EXEC["evidence"]["receipt_check"] = receipt
    record("the attestor's check releases the Receipt: it binds exactly the request the finalized snapshot names",
           releasable and receipt.get("response_hash") == response_hash and receipt.get("request_hash") == task["request_hash"] and
           receipt.get("artifact_digest") == artifact and receipt.get("report_digest") == report_object, receipt)
    if not releasable:
        return
    record("paid: the outcome binds the anchored Quote, execution, input, source, toolchain and manifest",
           outcome.get("quote_commitment") == receipt["quote_commitment"] == report.get("quote_commitment") and
           outcome.get("execution_id") == "sha256:" + task["execution_id"] and
           outcome.get("input_digest") == "sha256:" + task["input_digest"] and
           outcome.get("source_digest") == task["source_digest"] and outcome.get("toolchain_digest") == EXECUTOR_IMAGE and
           outcome.get("sandbox_digest") == LIFE["manifest_digest"],
           {"outcome": outcome, "anchored_quote_commitment": receipt["quote_commitment"], "source_digest": task["source_digest"]})
    settled = actor_settlement(LIFE["provider"], lambda: tosctl(
        "agent", "service", "send", "--operation", "respond", "--address", LIFE["actor"], "--from", "provider",
        "--request-id", str(request_id), "--response-hash", response_hash, "--attestor-controller", "service-attestor",
        "--yes"), [LIFE["provider"]])
    responded = wait_state(task["request_hash"], {"responded"})
    record("the buyer resolves the paid request as responded with exactly the Receipt hash",
           responded.get("response_hash") == response_hash, responded or LAST_STATUS_ERROR[0])
    flow = settled.get(LIFE["provider"]) or {}
    record("the provider wallet's respond reconciles exactly", flow.get("exact") is True, settled)
    EXEC["evidence"].update(responded=responded, respond_settlement=settled)

    # Negative control after respond: finalized state no longer proves a
    # pending request, so admission refuses before the slot is consulted;
    # nothing runs, the slots stay unchanged and the response stays the one
    # Receipt hash.
    slots_before = slot_state_digest()
    again_code, again = paid(task, inbox)
    slots_after = slot_state_digest()
    after = status_of(task["request_hash"])
    EXEC["evidence"]["rerun_responded"] = {"exit_code": again_code, "report": again, "slots_before": slots_before,
                                           "slots_after": slots_after, "status_after": after}
    record("paid again after respond: not admitted, not executed, slots and journal unchanged, still the one response",
           again_code == EXIT_NOT_ADMITTED and again.get("status") == "not_admitted" and not again.get("response_hash") and
           not again.get("outcome") and slots_before == slots_after and after.get("state") == "responded" and
           after.get("response_hash") == response_hash, EXEC["evidence"]["rerun_responded"])


def execute_failing() -> None:
    task = call_with_source("paid-fail", source_archive(passing=False))
    if not task["status"]:
        return
    inbox = deliver(task)
    code, report = paid(task, inbox)
    status = status_of(task["request_hash"])
    EXEC["evidence"]["execution_failed"] = {"request_id": task["status"]["request_id"], "request_hash": task["request_hash"],
                                            "exit_code": code, "report": report, "status_after": status}
    record("paid with a failing test: execution_failed, no Receipt hash, the request stays pending",
           code == EXIT_EXECUTION_FAILED and report.get("status") == "execution_failed" and
           report.get("slot_state") == "failed" and not report.get("response_hash") and
           not report.get("receipt_boc_base64") and status.get("state") == "pending",
           EXEC["evidence"]["execution_failed"])
    # The buyer's remedy is the refund path once the response deadline passes.
    EXEC["failed_request"] = {"request_hash": task["request_hash"], **task["status"]}


def execute() -> None:
    if "actor" not in LIFE:
        record("paid execution prerequisites are present", False, "acceptance did not complete")
        return
    EXEC["evidence"] = evidence.setdefault("execute", {})
    try:
        stage_provider_root()
    except Exception as error:  # noqa: BLE001 - the evidence records the failure
        record("the provider root state was staged without an exception", False, repr(error))
        return
    # Each case is recorded on its own, so a failure in one still lets the
    # other produce evidence.
    for name, case in (("completed", execute_passing), ("execution_failed", execute_failing)):
        try:
            case()
        except Exception as error:  # noqa: BLE001 - the evidence records the failure
            record(f"paid {name} case completed without an exception", False, repr(error))


evidence: dict = {}


async def main() -> int:
    global GLOBAL_CONFIG, TOSCTL_SHA256, TREE_STATUS
    if EXECUTE and (not EXECUTOR.is_file() or not TOS_AI_COMMIT):
        print("E2E_EXECUTE=1 needs E2E_EXECUTOR (the built software-work-execute) and E2E_TOS_AI_COMMIT", flush=True)
        return 2
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
    TREE_STATUS = subprocess.run(["git", "-C", str(REPO), "status", "--porcelain"], capture_output=True,
                                 text=True).stdout.strip().splitlines()
    evidence.update({"schema": "tos.service.service-actor-buyer.local-acceptance.v1",
                     "qualifies_as_public_acceptance": False,
                     "reason": "one host runs every validator and endpoint",
                     "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                     "tos_source": str(SOURCE), "tos_build": str(BUILD),
                     "tosctl": {"path": str(TOSCTL), "sha256": TOSCTL_SHA256},
                     "protocol_commit": subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True,
                                                       text=True).stdout.strip(),
                     "protocol_tree_status": TREE_STATUS, "protocol_tree_dirty": bool(TREE_STATUS),
                     "actor_code_hash": ACTOR_CODE_HASH, "network_label": NETWORK_LABEL,
                     "stand_ins": {
                         "manifest_store": "local directory of canonical manifest CBOR files named by sha256 digest",
                         "quote_source": "service-actor-e2e-fixture quote: pkg/quoteprovider over finalized state, no gateway"}})
    # The evidence names a commit; it is evidence for that commit only if the
    # run used exactly its tree.
    record("the protocol tree is clean at the commit the evidence names", not TREE_STATUS, TREE_STATUS or "clean")
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
            if EXECUTE:
                await asyncio.to_thread(execute)
            if LIFECYCLE:
                await asyncio.to_thread(lifecycle)
            if EXECUTE and LIFECYCLE and EXEC.get("failed_request"):
                # Hours have passed: the failed request's response deadline is
                # behind it, so the buyer takes its refund.
                await asyncio.to_thread(refund_path, EXEC["failed_request"])
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
