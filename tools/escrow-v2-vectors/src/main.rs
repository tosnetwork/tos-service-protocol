//! Runs the released stablecoin escrow v2 contract on a Go-built escrow and
//! records what the contract itself produces: the data cell after every
//! transition, its get-method answers, the settlement intent it accepts, and
//! the exit codes of the inputs it refuses.
//!
//! The settlement intent is built here independently of the Go codec, from
//! the contract's layout, and is recorded only after the contract accepted a
//! signature over it. Nothing in the output is taken from the Go codec without
//! the contract having consumed it.
//!
//! Usage: escrow-v2-vectors <tos-checkout> <tos-commit> <go-input.json>

use std::{env, fs, path::Path};

use anyhow::{Context, Result, anyhow, bail};
use chain_block::{
    BuilderData, Cell, Coins, Deserializable, IBitstring, MsgAddressInt, Serializable, SliceData,
    StateInit, TrComputePhase, TransactionDescr, UInt256, base64_decode, base64_encode,
    read_single_root_boc, write_boc,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tos_sandbox::{Blockchain, MessageBuilder, SendResult};

const TOS: u64 = 1_000_000_000;
const MAGIC_DATA: u32 = 0x4e45_5331;
const MAGIC_RUNTIME: u32 = 0x4e45_5231;
const MAGIC_INTENT: u32 = 0x4e53_4931;
const OP_RELEASE: u32 = 0x4e45_0001;
const OP_REFUND: u32 = 0x4e45_0002;
const OP_ACCEPT: u32 = 0x4e45_0003;
const OP_TRANSFER_NOTIFICATION: u32 = 0x7362_d09c;
const OP_INTERNAL_TRANSFER: u32 = 0x178d_4519;
const OP_TOP_UP: u32 = 0xd372_158c;
const ESCROW_SOURCE: &str = "crypto/smartcont/tos-service-stablecoin-escrow-v2.fc";
const ESCROW_BOC: &str = "crypto/smartcont/tos-service-stablecoin-escrow-v2.boc.base64";
const ESCROW_RELEASE: &str = "crypto/smartcont/tos-service-stablecoin-escrow-v2.release.json";
const WALLET_BOC: &str = "crypto/smartcont/test-usdt-wallet-code.boc.base64";
const GLOBAL_VERSION: u32 = 14;
const RELEASE_QUERY: u64 = 7;
const REFUND_QUERY: u64 = 9;

fn e<T, E: std::fmt::Display>(value: std::result::Result<T, E>, what: &str) -> Result<T> {
    value.map_err(|err| anyhow!("{what}: {err}"))
}

fn read_code(tos: &Path, file: &str) -> Result<(Cell, Vec<u8>)> {
    let text = fs::read_to_string(tos.join(file)).with_context(|| format!("read {file}"))?;
    let joined: String = text.split_whitespace().collect();
    let raw = e(base64_decode(&joined), file)?;
    let cell = e(read_single_root_boc(&raw), file)?;
    Ok((cell, raw))
}

fn decode_b64_cell(value: &Value, field: &str) -> Result<Cell> {
    let text = value[field].as_str().ok_or_else(|| anyhow!("missing {field}"))?;
    e(read_single_root_boc(e(base64_decode(text), field)?), field)
}

fn hex32(text: &str) -> Result<[u8; 32]> {
    let raw = e(hex::decode(text), "hex")?;
    raw.try_into().map_err(|_| anyhow!("expected 32 bytes"))
}

fn raw_address(text: &str) -> Result<MsgAddressInt> {
    let (wc, id) = text.split_once(':').ok_or_else(|| anyhow!("bad address {text}"))?;
    if wc != "0" {
        bail!("address {text} is not on workchain 0");
    }
    e(MsgAddressInt::with_params(0, UInt256::from(hex32(id)?)), "address")
}

fn address_text(address: &MsgAddressInt) -> Result<String> {
    let bytes = address.address().get_bytestring(0);
    if bytes.len() != 32 {
        bail!("address is not 256 bits");
    }
    Ok(format!("{}:{}", address.workchain_id(), hex::encode(bytes)))
}

fn boc(cell: &Cell) -> Result<String> {
    Ok(base64_encode(e(write_boc(cell), "write boc")?))
}

fn cell_hash_hex(cell: &Cell) -> String {
    hex::encode(cell.repr_hash().as_slice())
}

fn into_cell(builder: BuilderData) -> Result<Cell> {
    e(builder.into_cell(), "finalize cell")
}

fn exit_code(result: &SendResult) -> Result<(bool, i32)> {
    let tr = result.first_transaction().ok_or_else(|| anyhow!("no transaction"))?;
    let descr = e(tr.read_description(), "transaction description")?;
    let TransactionDescr::Ordinary(descr) = descr else {
        bail!("transaction is not ordinary");
    };
    match descr.compute_ph {
        TrComputePhase::Vm(vm) => Ok((descr.aborted, vm.exit_code)),
        TrComputePhase::Skipped(skipped) => bail!("compute phase skipped: {:?}", skipped.reason),
    }
}

fn expect_exit(result: &SendResult, want: i32, what: &str) -> Result<()> {
    let (aborted, code) = exit_code(result)?;
    if code != want || aborted != (want != 0) {
        bail!("{what}: expected exit {want}, got {code} (aborted {aborted})");
    }
    Ok(())
}

fn wallet_init(code: &Cell, owner: &MsgAddressInt, master: &MsgAddressInt) -> Result<StateInit> {
    let mut data = BuilderData::new();
    e(data.append_bits(0, 4), "wallet status")?;
    e(Coins::new(0).write_to(&mut data), "wallet balance")?;
    e(owner.write_to(&mut data), "wallet owner")?;
    e(master.write_to(&mut data), "wallet master")?;
    Ok(StateInit::with_code_and_data(code.clone(), into_cell(data)?))
}

fn init_address(init: &StateInit) -> Result<MsgAddressInt> {
    let cell = into_cell(e(init.write_to_new_cell(), "state init")?)?;
    e(MsgAddressInt::with_params(0, cell.repr_hash()), "address")
}

/// (status, funded, settled, receipt_hash, pending_query, accepted_at), read
/// with the contract's own storage layout.
fn runtime(data: &Cell) -> Result<Value> {
    let mut root = e(SliceData::load_cell(data.clone()), "data")?;
    if e(root.get_next_u32(), "magic")? != MAGIC_DATA || e(root.get_next_u16(), "version")? != 2 {
        bail!("contract data is not escrow v2");
    }
    let status = e(root.get_next_byte(), "status")?;
    e(root.move_by(256 * 3), "hashes")?;
    for _ in 0..3 {
        e(root.checked_drain_reference(), "ref")?;
    }
    let runtime = e(root.checked_drain_reference(), "runtime")?;
    let mut r = e(SliceData::load_cell(runtime), "runtime")?;
    if e(r.get_next_u32(), "magic")? != MAGIC_RUNTIME || e(r.get_next_u16(), "version")? != 2 {
        bail!("contract runtime is not version 2");
    }
    let funded = e(r.get_next_u128(), "funded")?;
    let settled = e(r.get_next_u128(), "settled")?;
    let receipt = e(r.get_next_u256(), "receipt")?;
    let query = e(r.get_next_u64(), "query")?;
    let accepted = e(r.get_next_u64(), "accepted_at")?;
    Ok(json!({
        "status": status, "funded": funded.to_string(), "settled": settled.to_string(),
        "receipt_hash": hex::encode(receipt), "pending_query": query, "accepted_at": accepted,
    }))
}

struct Escrow {
    bc: Blockchain,
    relayer: MsgAddressInt,
    escrow: MsgAddressInt,
    own_wallet: MsgAddressInt,
    buyer: MsgAddressInt,
}

impl Escrow {
    /// Deploys `init` and the escrow's own stablecoin wallet, credited with
    /// `amount`, at time `base`.
    fn deploy(init: StateInit, wallet_code: &Cell, input: &Value, amount: u64, base: u32) -> Result<Self> {
        let mut bc = e(Blockchain::with_global_version_and_base_workchain(GLOBAL_VERSION), "sandbox")?;
        bc.set_workchain(0);
        bc.set_now(base);
        let relayer = e(bc.treasury("escrow-v2-vector-relayer", 1_000 * TOS), "treasury")?.address().clone();
        let escrow = init_address(&init)?;
        let buyer = raw_address(input["buyer_address"].as_str().unwrap_or_default())?;
        let master = raw_address(input["asset_master_address"].as_str().unwrap_or_default())?;
        let deploy = e(
            bc.send_message(
                MessageBuilder::internal(&relayer, &escrow, 20 * TOS)
                    .bounce(false)
                    .state_init(init)
                    .body(into_cell(BuilderData::new())?)
                    .build(),
            ),
            "deploy",
        )?;
        expect_exit(&deploy, 0, "deploy")?;
        let own_init = wallet_init(wallet_code, &escrow, &master)?;
        let own_wallet = init_address(&own_init)?;
        let mut top_up = BuilderData::new();
        e(top_up.append_u32(OP_TOP_UP), "top up")?;
        let deployed = e(
            bc.send_message(
                MessageBuilder::internal(&master, &own_wallet, 20 * TOS)
                    .bounce(false)
                    .state_init(own_init)
                    .body(into_cell(top_up)?)
                    .build(),
            ),
            "wallet deploy",
        )?;
        expect_exit(&deployed, 0, "wallet deploy")?;
        let mut mint = BuilderData::new();
        e(mint.append_u32(OP_INTERNAL_TRANSFER), "mint")?;
        e(mint.append_u64(1), "mint")?;
        e(Coins::new(amount).write_to(&mut mint), "mint")?;
        e(buyer.write_to(&mut mint), "mint")?;
        e(mint.append_bits(0, 2), "mint")?;
        e(Coins::new(0).write_to(&mut mint), "mint")?;
        e(mint.append_bit_zero(), "mint")?;
        let minted = e(
            bc.send_message(MessageBuilder::internal(&master, &own_wallet, TOS).body(into_cell(mint)?).build()),
            "mint",
        )?;
        expect_exit(&minted, 0, "mint")?;
        Ok(Self { bc, relayer, escrow, own_wallet, buyer })
    }

    fn send(&mut self, from: &MsgAddressInt, body: Cell) -> Result<SendResult> {
        e(
            self.bc.send_message(MessageBuilder::internal(from, &self.escrow, TOS).body(body).build()),
            "send",
        )
    }

    fn data(&self) -> Result<Cell> {
        self.bc
            .get_account(&self.escrow)
            .and_then(|account| account.get_data())
            .ok_or_else(|| anyhow!("escrow has no data"))
    }

    fn snapshot(&self, at: u32, body: &Cell, result: &SendResult) -> Result<Value> {
        let (_, code) = exit_code(result)?;
        let data = self.data()?;
        Ok(json!({
            "at_unix": at, "body_boc_base64": boc(body)?, "exit_code": code,
            "data_boc_base64": boc(&data)?, "data_hash": cell_hash_hex(&data), "runtime": runtime(&data)?,
        }))
    }

    fn global_id(&self) -> Result<i32> {
        match e(self.bc.config_params().config(19), "config 19")? {
            Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => Ok(id as i32),
            other => bail!("parameter 19 is not the global id: {other:?}"),
        }
    }

    fn fund_body(&self, amount: u64) -> Result<Cell> {
        let mut body = BuilderData::new();
        e(body.append_u32(OP_TRANSFER_NOTIFICATION), "notification")?;
        e(body.append_u64(3), "notification")?;
        e(Coins::new(amount).write_to(&mut body), "notification")?;
        e(self.buyer.write_to(&mut body), "notification")?;
        e(body.append_bit_zero(), "notification")?;
        into_cell(body)
    }
}

/// The settlement intent as the contract rebuilds it before checking the
/// release signature (`settlement_intent` in the contract source).
fn intent_v2(global_id: i32, query: u64, charged: u128, escrow: &MsgAddressInt, quote: &[u8; 32], receipt: &[u8; 32]) -> Result<Cell> {
    let mut hashes = BuilderData::new();
    e(hashes.append_raw(quote, 256), "intent")?;
    e(hashes.append_raw(receipt, 256), "intent")?;
    let mut intent = BuilderData::new();
    e(intent.append_u32(MAGIC_INTENT), "intent")?;
    e(intent.append_u16(2), "intent")?;
    e(intent.append_i32(global_id), "intent")?;
    e(intent.append_u64(query), "intent")?;
    e(intent.append_u128(charged), "intent")?;
    e(escrow.write_to(&mut intent), "intent")?;
    e(intent.checked_append_reference(into_cell(hashes)?), "intent")?;
    into_cell(intent)
}

/// The retired version 1 layout: no network, hashes inline.
fn intent_v1(query: u64, charged: u128, escrow: &MsgAddressInt, quote: &[u8; 32], receipt: &[u8; 32]) -> Result<Cell> {
    let mut intent = BuilderData::new();
    e(intent.append_u32(MAGIC_INTENT), "intent")?;
    e(intent.append_u16(1), "intent")?;
    e(intent.append_u64(query), "intent")?;
    e(intent.append_u128(charged), "intent")?;
    e(escrow.write_to(&mut intent), "intent")?;
    e(intent.append_raw(quote, 256), "intent")?;
    e(intent.append_raw(receipt, 256), "intent")?;
    into_cell(intent)
}

fn release_body(signer: &SigningKey, intent: &Cell, query: u64, receipt: &Cell) -> Result<(Cell, [u8; 64])> {
    let signature = signer.sign(intent.repr_hash().as_slice()).to_bytes();
    let mut body = BuilderData::new();
    e(body.append_u32(OP_RELEASE), "release")?;
    e(body.append_u64(query), "release")?;
    e(body.append_raw(&signature, 512), "release")?;
    e(body.checked_append_reference(receipt.clone()), "release")?;
    Ok((into_cell(body)?, signature))
}

fn accept_body(query: u64, quote: &[u8; 32], offer: &[u8; 32]) -> Result<Cell> {
    let mut body = BuilderData::new();
    e(body.append_u32(OP_ACCEPT), "accept")?;
    e(body.append_u64(query), "accept")?;
    e(body.append_raw(quote, 256), "accept")?;
    e(body.append_raw(offer, 256), "accept")?;
    into_cell(body)
}

/// Returns `data` with its version field rewritten to `version`, all else
/// unchanged.
fn with_data_version(data: &Cell, version: u16) -> Result<Cell> {
    let mut source = e(SliceData::load_cell(data.clone()), "data")?;
    let magic = e(source.get_next_u32(), "magic")?;
    e(source.get_next_u16(), "version")?;
    let mut out = BuilderData::new();
    e(out.append_u32(magic), "data")?;
    e(out.append_u16(version), "data")?;
    e(out.checked_append_references_and_data(&source), "data")?;
    into_cell(out)
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        bail!("usage: escrow-v2-vectors <tos-checkout> <tos-commit> <go-input.json>");
    }
    let tos = Path::new(&args[1]);
    let input: Value = serde_json::from_str(&fs::read_to_string(&args[3]).context("read input")?)?;

    let (code, code_raw) = read_code(tos, ESCROW_BOC)?;
    let (wallet_code, _) = read_code(tos, WALLET_BOC)?;
    let release: Value = serde_json::from_str(&fs::read_to_string(tos.join(ESCROW_RELEASE))?)?;
    let code_hash = format!("tvm-cell-sha256:{}", cell_hash_hex(&code));
    let boc_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&code_raw)));
    if release["code_hash"] != json!(code_hash) || release["boc_sha256"] != json!(boc_sha256) {
        bail!("frozen escrow BOC does not match its release manifest");
    }
    if input["escrow_code_hash"] != json!(code_hash) {
        bail!("input was built for different escrow code");
    }
    if input["asset_wallet_code_hash"] != json!(format!("tvm-cell-sha256:{}", cell_hash_hex(&wallet_code))) {
        bail!("input was built for a different wallet code");
    }

    let state_init_cell = decode_b64_cell(&input, "state_init_boc_base64")?;
    let state_init = e(StateInit::construct_from_cell(state_init_cell), "state init")?;
    if state_init.code().map(cell_hash_hex) != Some(cell_hash_hex(&code)) {
        bail!("input StateInit does not carry the frozen escrow code");
    }
    let initial_data = state_init.data().cloned().ok_or_else(|| anyhow!("state init has no data"))?;
    let base = u32::try_from(input["base_unix"].as_u64().unwrap_or_default())?;
    let amount: u64 = input["amount_atomic"].as_str().unwrap_or_default().parse()?;
    let quote_hash = hex32(input["quote_commitment"].as_str().unwrap_or_default().trim_start_matches("tvm-cell-sha256:"))?;
    let offer = hex32(input["provider_offer_digest"].as_str().unwrap_or_default().trim_start_matches("sha256:"))?;
    let accept_query = input["accept_query_id"].as_u64().unwrap_or_default();
    let refund_at = u32::try_from(input["refund_available_at"].as_u64().unwrap_or_default())?;
    let receipt = decode_b64_cell(&input, "receipt_boc_base64")?;
    let receipt_hash: [u8; 32] = *receipt.repr_hash().as_slice();
    let signer = SigningKey::from_bytes(&hex32(input["signer_seed_hex"].as_str().unwrap_or_default())?);
    if hex::encode(signer.verifying_key().to_bytes()) != input["signer_public_key_hex"].as_str().unwrap_or_default() {
        bail!("signer seed does not match the committed public key");
    }

    // Release path: deploy, accept, fund, refused releases, release.
    let mut chain = Escrow::deploy(state_init.clone(), &wallet_code, &input, amount, base)?;
    if address_text(&chain.escrow)? != input["escrow_address"].as_str().unwrap_or_default() {
        bail!("contract address differs from the Go escrow address");
    }
    let global_id = chain.global_id()?;
    let state = e(chain.bc.run_get_method(&chain.escrow, "get_escrow_state", Vec::new()), "get_escrow_state")?;
    state.expect_success();
    let wallet = e(chain.bc.run_get_method(&chain.escrow, "get_escrow_wallet", Vec::new()), "get_escrow_wallet")?;
    wallet.expect_success();
    let mut wallet_slice = wallet.slice_at(0);
    let wallet_address = e(MsgAddressInt::construct_from(&mut wallet_slice), "wallet address")?;
    if wallet_address != chain.own_wallet {
        bail!("contract reports a different own wallet than the standard derivation");
    }
    let deployed = json!({
        "data_boc_base64": boc(&chain.data()?)?, "data_hash": cell_hash_hex(&chain.data()?),
        "runtime": runtime(&chain.data()?)?,
        "get_escrow_state": (0..6).map(|i| state.int_at(i).to_string()).collect::<Vec<_>>(),
        "get_escrow_wallet": address_text(&wallet_address)?,
    });

    let accept = accept_body(accept_query, &quote_hash, &offer)?;
    if cell_hash_hex(&accept) != cell_hash_hex(&decode_b64_cell(&input, "accept_body_boc_base64")?) {
        bail!("Go accept body differs from the contract's accept layout");
    }
    chain.bc.set_now(base + 10);
    let buyer = chain.buyer.clone();
    let result = chain.send(&buyer, accept.clone())?;
    expect_exit(&result, 0, "accept")?;
    let accepted = chain.snapshot(base + 10, &accept, &result)?;

    chain.bc.set_now(base + 20);
    let funding = chain.fund_body(amount)?;
    let wallet = chain.own_wallet.clone();
    let result = chain.send(&wallet, funding.clone())?;
    expect_exit(&result, 0, "fund")?;
    let funded = chain.snapshot(base + 20, &funding, &result)?;
    if funded["runtime"]["status"] != json!(2) {
        bail!("funding did not reach the funded state");
    }

    let release_at = base + 40;
    chain.bc.set_now(release_at);
    let relayer = chain.relayer.clone();
    let mut refused = Vec::new();
    let v1 = intent_v1(RELEASE_QUERY, u128::from(amount), &chain.escrow, &quote_hash, &receipt_hash)?;
    let (body, _) = release_body(&signer, &v1, RELEASE_QUERY, &receipt)?;
    let result = chain.send(&relayer, body.clone())?;
    expect_exit(&result, 2407, "version 1 intent")?;
    refused.push(json!({"case": "release signed over the version 1 intent layout",
        "intent_boc_base64": boc(&v1)?, "body_boc_base64": boc(&body)?, "exit_code": 2407}));
    let other = intent_v2(global_id.wrapping_add(1), RELEASE_QUERY, u128::from(amount), &chain.escrow, &quote_hash, &receipt_hash)?;
    let (body, _) = release_body(&signer, &other, RELEASE_QUERY, &receipt)?;
    let result = chain.send(&relayer, body.clone())?;
    expect_exit(&result, 2407, "intent for another network")?;
    refused.push(json!({"case": "release signed for another network's global id",
        "global_id": global_id.wrapping_add(1), "intent_boc_base64": boc(&other)?, "body_boc_base64": boc(&body)?,
        "exit_code": 2407}));
    if chain.data()?.repr_hash() != funded_hash(&funded)? {
        bail!("a refused release changed escrow state");
    }

    let intent = intent_v2(global_id, RELEASE_QUERY, u128::from(amount), &chain.escrow, &quote_hash, &receipt_hash)?;
    let (body, signature) = release_body(&signer, &intent, RELEASE_QUERY, &receipt)?;
    let result = chain.send(&relayer, body.clone())?;
    expect_exit(&result, 0, "release")?;
    let mut released = chain.snapshot(release_at, &body, &result)?;
    if released["runtime"]["status"] != json!(3) {
        bail!("release did not reach release_pending");
    }
    released["query_id"] = json!(RELEASE_QUERY);
    released["charged"] = json!(amount.to_string());
    released["intent_boc_base64"] = json!(boc(&intent)?);
    released["intent_hash"] = json!(cell_hash_hex(&intent));
    released["signature_hex"] = json!(hex::encode(signature));

    // Refund path on a fresh chain.
    let mut chain = Escrow::deploy(state_init.clone(), &wallet_code, &input, amount, base)?;
    chain.bc.set_now(base + 10);
    let result = chain.send(&buyer, accept.clone())?;
    expect_exit(&result, 0, "accept")?;
    chain.bc.set_now(base + 20);
    let wallet = chain.own_wallet.clone();
    let result = chain.send(&wallet, funding.clone())?;
    expect_exit(&result, 0, "fund")?;
    chain.bc.set_now(refund_at);
    let mut refund = BuilderData::new();
    e(refund.append_u32(OP_REFUND), "refund")?;
    e(refund.append_u64(REFUND_QUERY), "refund")?;
    let refund = into_cell(refund)?;
    let relayer = chain.relayer.clone();
    let result = chain.send(&relayer, refund.clone())?;
    expect_exit(&result, 0, "refund")?;
    let mut refunded = chain.snapshot(refund_at, &refund, &result)?;
    if refunded["runtime"]["status"] != json!(4) {
        bail!("refund did not reach refund_pending");
    }
    refunded["query_id"] = json!(REFUND_QUERY);

    // A version 1 data cell under the same code is refused on every message.
    let v1_data = with_data_version(&initial_data, 1)?;
    let v1_init = StateInit::with_code_and_data(code.clone(), v1_data.clone());
    let mut chain = Escrow::deploy(v1_init, &wallet_code, &input, amount, base)?;
    chain.bc.set_now(base + 10);
    let result = chain.send(&buyer, accept.clone())?;
    expect_exit(&result, 2401, "version 1 data")?;
    refused.push(json!({"case": "escrow data at version 1", "data_boc_base64": boc(&v1_data)?,
        "body_boc_base64": boc(&accept)?, "exit_code": 2401}));

    let commit = &args[2];
    let output = json!({
        "schema": "tos.service.escrow-v2-contract-vectors.v1",
        "provenance": {
            "tos_commit": commit,
            "escrow_source": ESCROW_SOURCE,
            "escrow_code_artifact": ESCROW_BOC,
            "escrow_code_hash": code_hash,
            "escrow_code_boc_sha256": boc_sha256,
            "wallet_code_artifact": WALLET_BOC,
            "executor": "tosctl/src/sandbox (tos_sandbox), global version 14, workchain 0",
            "command": "scripts/generate-escrow-v2-vectors.sh <tos-checkout>",
        },
        "global_id": global_id,
        "input": input,
        "deployed": deployed,
        "accepted": accepted,
        "funded": funded,
        "released": released,
        "refunded": refunded,
        "refused": refused,
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn funded_hash(funded: &Value) -> Result<UInt256> {
    Ok(UInt256::from(hex32(funded["data_hash"].as_str().unwrap_or_default())?))
}
