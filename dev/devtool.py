"""Operator tool for the RillSwap regtest dev stack (dev/compose.yaml).

Runs inside the rillswap-dev image. `bootstrap` is idempotent: every step
checks current state before acting, so rerunning it after a restart or an
interrupted attempt only completes what is missing. All state lives under
/state (a named Docker volume) and is disposable regtest data.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx

STATE = Path(os.environ.get("RILL_DEV_STATE", "/state"))
SRC = Path(os.environ.get("RILL_DEV_SRC", "/src"))
CRYPTO = os.environ.get("RILL_CRYPTO_LIBRARY", "/opt/rill/native/librill_crypto.so")
NETWORK_FIXTURE = SRC / "rill-provider/tests/fixtures/initial-btc-to-ln-v1.json"

CORE_URL = "http://bitcoind:18443"
CORE_AUTH = ("rill", "rill-dev-regtest")
# Matches the static `-rpcauth=__cookie__:...` entry in compose.yaml, so the
# cookie file Rill reads stays valid across bitcoind restarts.
CORE_COOKIE = "__cookie__:rill-dev-regtest-cookie\n"
LOCAL_CORE_PORT = 18443
LOCAL_LND_PORT = 10009

RELAY_INTERNAL = os.environ.get("RILL_DEV_RELAY_INTERNAL", "ws://relay:8080")
RELAY_HOST = os.environ.get("RILL_DEV_RELAY_HOST", "ws://127.0.0.1:7777")

LND_NODES = ("maker", "user")
DIRECTIONS = ("btc-to-ln", "ln-to-btc")
CHANNEL_SAT = 5_000_000
LND_FUND_BTC = 10
CORE_FUND_BTC = 10
MATURE_HEIGHT = 150


def log(message: str) -> None:
    print(f"[devtool {time.strftime('%H:%M:%S')}] {message}", flush=True)


def private_write(path: Path, data: str | bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data.encode() if isinstance(data, str) else data)
    tmp.chmod(mode)
    tmp.replace(path)


def wait_for(what: str, check: Any, timeout: float = 120, interval: float = 1) -> Any:
    deadline = time.monotonic() + timeout
    while True:
        try:
            result = check()
        except (httpx.HTTPError, RpcError):
            result = None
        if result:
            return result
        if time.monotonic() > deadline:
            raise SystemExit(f"timed out waiting for {what}")
        time.sleep(interval)


class RpcError(RuntimeError):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


class Core:
    """Bitcoin Core JSON-RPC over the compose network (rpcauth user)."""

    def __init__(self, wallet: str | None = None) -> None:
        self.wallet = wallet

    def __call__(self, method: str, *params: Any) -> Any:
        path = f"/wallet/{self.wallet}" if self.wallet else "/"
        body = {"jsonrpc": "1.0", "id": "dev", "method": method, "params": list(params)}
        response = httpx.post(CORE_URL + path, json=body, auth=CORE_AUTH, timeout=120)
        payload = response.json()
        if payload.get("error"):
            raise RpcError(payload["error"]["code"], payload["error"]["message"])
        return payload["result"]


class Lnd:
    """LND REST client using credentials copied to /state/lnd/<node>."""

    def __init__(self, node: str) -> None:
        self.node = node
        creds = STATE / "lnd" / node
        macaroon = (creds / "admin.macaroon").read_bytes().hex()
        self.client = httpx.Client(
            base_url=f"https://lnd-{node}:8080",
            verify=str(creds / "tls.cert"),
            headers={"Grpc-Metadata-macaroon": macaroon},
            timeout=120,
        )

    def get(self, path: str, **params: Any) -> Any:
        response = self.client.get(path, params=params)
        response.raise_for_status()
        return response.json()

    def post(self, path: str, body: dict[str, Any]) -> Any:
        response = self.client.post(path, json=body)
        if response.status_code >= 400:
            raise SystemExit(f"lnd-{self.node} {path}: {response.text}")
        return response.json()

    def info(self) -> dict[str, Any]:
        return self.get("/v1/getinfo")

    def pubkey(self) -> str:
        return self.info()["identity_pubkey"]

    def new_address(self) -> str:
        return self.get("/v1/newaddress", type="TAPROOT_PUBKEY")["address"]

    def onchain_sat(self) -> int:
        return int(self.get("/v1/balance/blockchain").get("confirmed_balance", 0))

    def channels(self) -> list[dict[str, Any]]:
        return self.get("/v1/channels").get("channels", [])

    def pending_open(self) -> list[dict[str, Any]]:
        return self.get("/v1/channels/pending").get("pending_open_channels", [])

    def add_invoice(self, sat: int, memo: str) -> str:
        return self.post("/v1/invoices", {"value": str(sat), "memo": memo})["payment_request"]

    def pay(self, bolt11: str) -> dict[str, Any]:
        return self.post("/v1/channels/transactions", {"payment_request": bolt11})


def copy_lnd_credentials(node: str) -> None:
    source = Path("/lnd") / node
    target = STATE / "lnd" / node
    wait_for(f"lnd-{node} credentials", lambda: (source / "tls.cert").exists(), timeout=60)
    private_write(target / "tls.cert", (source / "tls.cert").read_bytes(), 0o644)
    macaroon = source / "data/chain/bitcoin/regtest/admin.macaroon"
    wait_for(f"lnd-{node} macaroon", macaroon.exists, timeout=60)
    private_write(target / "admin.macaroon", macaroon.read_bytes())


def network_identity() -> dict[str, Any]:
    return json.loads(NETWORK_FIXTURE.read_text())["network_identity"]


def miner_address() -> str:
    path = STATE / "miner.address"
    if not path.exists():
        private_write(path, Core("miner")("getnewaddress", "", "bech32m"), 0o644)
    return path.read_text().strip()


def mine(blocks: int) -> int:
    Core()("generatetoaddress", blocks, miner_address())
    return Core()("getblockcount")


# --- bootstrap ---------------------------------------------------------------


def ensure_wallet(name: str) -> None:
    core = Core()
    if name in core("listwallets"):
        return
    try:
        core("loadwallet", name)
    except RpcError:
        core("createwallet", name)


def wait_lnd_synced(nodes: list[Lnd]) -> None:
    def synced() -> bool:
        height = Core()("getblockcount")
        return all(
            (info := node.info())["synced_to_chain"] and int(info["block_height"]) == height
            for node in nodes
        )

    wait_for("LND chain sync", synced, timeout=180)


def ensure_chain_and_funds(lnds: dict[str, Lnd]) -> None:
    for wallet in ("miner", "user", "maker"):
        ensure_wallet(wallet)
    height = Core()("getblockcount")
    if height < MATURE_HEIGHT:
        log(f"mining {MATURE_HEIGHT - height} blocks for mature coins")
        mine(MATURE_HEIGHT - height)
    funded = False
    miner = Core("miner")
    for node, lnd in lnds.items():
        # total_balance includes unconfirmed change from a pending channel open.
        if int(lnd.get("/v1/balance/blockchain").get("total_balance", 0)) < 100_000_000:
            log(f"funding lnd-{node} with {LND_FUND_BTC} BTC")
            miner("sendtoaddress", lnd.new_address(), LND_FUND_BTC)
            funded = True
    for wallet in ("user", "maker"):
        if Core(wallet)("getbalances")["mine"]["trusted"] < 1:
            log(f"funding Core wallet {wallet} with {CORE_FUND_BTC} BTC")
            address = Core(wallet)("getnewaddress", "", "bech32m")
            miner("sendtoaddress", address, CORE_FUND_BTC)
            funded = True
    if funded:
        mine(6)
    wait_lnd_synced(list(lnds.values()))
    for node, lnd in lnds.items():
        wait_for(f"lnd-{node} confirmed funds", lambda lnd=lnd: lnd.onchain_sat() > 0, timeout=60)


def has_channel(local: Lnd, remote_pubkey: str) -> bool:
    """True when `local` opened (or is opening) a channel to `remote_pubkey`."""
    for channel in local.channels():
        if channel["remote_pubkey"] == remote_pubkey and channel.get("initiator"):
            return True
    for pending in local.pending_open():
        channel = pending["channel"]
        if channel["remote_node_pub"] == remote_pubkey and channel["initiator"] in (
            "INITIATOR_LOCAL",
            "INITIATOR_BOTH",
        ):
            return True
    return False


def ensure_channels(lnds: dict[str, Lnd]) -> None:
    maker, user = lnds["maker"], lnds["user"]
    pubkeys = {node: lnd.pubkey() for node, lnd in lnds.items()}
    peers = {peer["pub_key"] for peer in user.get("/v1/peers").get("peers", [])}
    if pubkeys["maker"] not in peers:
        user.client.post(
            "/v1/peers",
            json={"addr": {"pubkey": pubkeys["maker"], "host": "lnd-maker:9735"}, "perm": True},
        )
        wait_for(
            "peer connection",
            lambda: any(
                p["pub_key"] == pubkeys["maker"] for p in user.get("/v1/peers").get("peers", [])
            ),
        )
    opened = False
    # maker -> user gives the maker outbound liquidity for BTC->LN payouts;
    # user -> maker lets the user pay the maker's LN->BTC hold invoices.
    for local, remote in (("maker", "user"), ("user", "maker")):
        if has_channel(lnds[local], pubkeys[remote]):
            continue
        log(f"opening {CHANNEL_SAT} sat channel {local} -> {remote}")
        lnds[local].post(
            "/v1/channels",
            {
                "node_pubkey": base64.b64encode(bytes.fromhex(pubkeys[remote])).decode(),
                "local_funding_amount": str(CHANNEL_SAT),
                "sat_per_vbyte": "2",
            },
        )
        opened = True
    if opened or maker.pending_open() or user.pending_open():
        mine(6)
    wait_for(
        "active channels",
        lambda: sum(1 for c in maker.channels() if c.get("active")) >= 2,
        timeout=120,
    )


def provision_maker(direction: str, xonly_by_direction: dict[str, str]) -> None:
    home = STATE / "makers" / direction
    home.mkdir(parents=True, exist_ok=True)
    home.chmod(0o700)
    # Credentials are refreshed on every run; the config refers to them relatively.
    private_write(home / "core.cookie", CORE_COOKIE)
    private_write(home / "tls.cert", (STATE / "lnd/maker/tls.cert").read_bytes(), 0o644)
    private_write(home / "admin.macaroon", (STATE / "lnd/maker/admin.macaroon").read_bytes())

    custody = home / "custody.key"
    if not custody.exists():
        from pyrage import x25519

        identity = x25519.Identity.generate()
        private_write(custody, f"{identity}\n")
        private_write(home / "custody.recipient", f"{identity.to_public()}\n", 0o644)
    recipient = (home / "custody.recipient").read_text().strip()

    identity_file = home / "provider-identity.age"
    xonly_file = home / "provider.xonly"
    if not xonly_file.exists():
        # An identity without its recorded public key is an interrupted
        # attempt from before any config or store referenced it.
        identity_file.unlink(missing_ok=True)
        result = subprocess.run(
            [
                "rill-provider",
                "provision-identity",
                "--out",
                str(identity_file),
                "--recipient",
                recipient,
                "--native-crypto-library",
                CRYPTO,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        private_write(xonly_file, result.stdout.strip() + "\n", 0o644)
    xonly = xonly_file.read_text().strip()
    xonly_by_direction[direction] = xonly

    config_path = home / "provider.json"
    if not config_path.exists():
        maker_wallet = Core("maker")
        address = maker_wallet("getnewaddress", f"{direction}-destination", "bech32m")
        profile = f"{direction}/v1"
        config: dict[str, Any] = {
            "network": network_identity(),
            "provider_identity_xonly": xonly,
            "identity_file": "provider-identity.age",
            "store_path": "provider-store/live.sqlite",
            "custody_recipient": recipient,
            "custody_identity_file": "custody.key",
            "native_crypto_library": CRYPTO,
            "bitcoin_core": {"port": LOCAL_CORE_PORT, "cookie_file": "core.cookie"},
            "lnd": {
                "port": LOCAL_LND_PORT,
                "tls_certificate": "tls.cert",
                "macaroon": "admin.macaroon",
                "payment_macaroon": "admin.macaroon",
            },
            "provider_destination_script": maker_wallet("getaddressinfo", address)["scriptPubKey"],
            "authority": {
                "volume_label": f"dev-{direction}",
                "outside_restore_domain": True,
                "single_host": True,
            },
            "handshake": {
                "profile": profile,
                "features": ["cooperative-claim/v1"],
                "encryption_suites": ["noise-xk-secp256k1-chachapoly-sha256/v1"],
                "capabilities": ["core/v1", "recovery/v1"],
            },
            "terms": {
                "profiles": [profile],
                "amount_bands": [[1000, 1_000_000]],
                "base_fee_sat": 50,
                "proportional_millionths": 1000,
                "slot": f"dev-{direction}",
            },
            "relay_urls": [RELAY_INTERNAL],
        }
        if direction == "ln-to-btc":
            config["bitcoin_core"]["wallet"] = "maker"
            config["lnd"]["invoices_macaroon"] = "admin.macaroon"
        private_write(config_path, json.dumps(config, indent=1) + "\n")

    store = home / "provider-store"
    if not (store / "live.sqlite").exists():
        if store.exists():
            shutil.rmtree(store)  # interrupted provisioning, never served
        store.mkdir(mode=0o700)
        log(f"provisioning {direction} maker store")
        subprocess.run(
            ["rill-provider", "provision-store", "--config", str(config_path)], check=True
        )


def provision_user() -> None:
    home = STATE / "user"
    (home / "swaps").mkdir(parents=True, exist_ok=True)
    home.chmod(0o700)
    private_write(home / "core.cookie", CORE_COOKIE)
    private_write(home / "tls.cert", (STATE / "lnd/user/tls.cert").read_bytes(), 0o644)
    private_write(home / "admin.macaroon", (STATE / "lnd/user/admin.macaroon").read_bytes())
    private_write(home / "network.json", json.dumps(network_identity()) + "\n", 0o644)
    if not (home / "age.key").exists():
        from pyrage import x25519

        identity = x25519.Identity.generate()
        private_write(home / "age.key", f"{identity}\n")
        private_write(home / "age.recipient", f"{identity.to_public()}\n", 0o644)


def write_info(lnds: dict[str, Lnd], makers: dict[str, str]) -> dict[str, Any]:
    info = {
        "makers": makers,
        "relay": {"containers": RELAY_INTERNAL, "host": RELAY_HOST},
        "lnd_pubkeys": {node: lnd.pubkey() for node, lnd in lnds.items()},
        "user_age_recipient": (STATE / "user/age.recipient").read_text().strip(),
        "network": network_identity(),
    }
    private_write(STATE / "info.json", json.dumps(info, indent=1) + "\n", 0o644)
    return info


def cmd_bootstrap(_: argparse.Namespace) -> None:
    STATE.mkdir(parents=True, exist_ok=True)
    wait_for("bitcoind", lambda: Core()("getblockcount") is not None)
    for node in LND_NODES:
        copy_lnd_credentials(node)
    lnds = {node: Lnd(node) for node in LND_NODES}
    wait_for("LND servers", lambda: all(lnd.info() for lnd in lnds.values()))
    ensure_chain_and_funds(lnds)
    ensure_channels(lnds)
    makers: dict[str, str] = {}
    for direction in DIRECTIONS:
        provision_maker(direction, makers)
    provision_user()
    write_info(lnds, makers)
    log(f"bootstrap complete at height {Core()('getblockcount')}")


# --- miner -------------------------------------------------------------------


def cmd_mine_loop(_: argparse.Namespace) -> None:
    interval = float(os.environ.get("RILL_DEV_BLOCK_SECONDS", "10"))
    paused = STATE / "miner.paused"
    log(f"auto-mining one block every {interval:g}s (0 disables; pause with `devctl miner pause`)")
    while True:
        time.sleep(interval if interval > 0 else 60)
        if interval <= 0 or paused.exists():
            continue
        try:
            mine(1)
        except (httpx.HTTPError, RpcError) as error:
            log(f"mining failed: {error}")


def cmd_mine(args: argparse.Namespace) -> None:
    print(f"height {mine(args.blocks)}")


def cmd_miner(args: argparse.Namespace) -> None:
    flag = STATE / "miner.paused"
    if args.action == "pause":
        flag.touch()
    elif args.action == "resume":
        flag.unlink(missing_ok=True)
    print("auto-miner " + ("paused" if flag.exists() else "running"))


# --- user commands -----------------------------------------------------------


def load_info() -> dict[str, Any]:
    path = STATE / "info.json"
    if not path.exists():
        raise SystemExit("stack not bootstrapped yet; run `devctl up` and wait for bootstrap")
    return json.loads(path.read_text())


def lnd_summary(node: str) -> dict[str, int]:
    lnd = Lnd(node)
    channels = lnd.channels()
    return {
        "onchain_sat": lnd.onchain_sat(),
        "channel_local_sat": sum(int(c.get("local_balance", 0)) for c in channels),
        "channel_remote_sat": sum(int(c.get("remote_balance", 0)) for c in channels),
    }


def balances() -> dict[str, Any]:
    result: dict[str, Any] = {}
    for wallet in ("user", "maker"):
        mine_balances = Core(wallet)("getbalances")["mine"]
        result[f"core:{wallet}"] = {
            "trusted_btc": mine_balances["trusted"],
            "pending_btc": mine_balances["untrusted_pending"],
        }
    for node in LND_NODES:
        result[f"lnd:{node}"] = lnd_summary(node)
    return result


def cmd_info(args: argparse.Namespace) -> None:
    info = load_info()
    info["height"] = Core()("getblockcount")
    info["auto_miner"] = "paused" if (STATE / "miner.paused").exists() else "running"
    info["balances"] = balances()
    if args.json:
        print(json.dumps(info, indent=1))
        return
    print(f"height          {info['height']} (auto-miner {info['auto_miner']})")
    print(f"relay (host)    {info['relay']['host']}")
    print(f"relay (stack)   {info['relay']['containers']}")
    for direction, xonly in info["makers"].items():
        print(f"maker {direction:<9} {xonly}")
    print(f"user age key    {info['user_age_recipient']}")
    for name, value in info["balances"].items():
        print(f"{name:<15} {json.dumps(value)}")


def cmd_balances(_: argparse.Namespace) -> None:
    print(json.dumps(balances(), indent=1))


def cmd_invoice(args: argparse.Namespace) -> None:
    print(Lnd(args.node).add_invoice(args.sat, args.memo))


def cmd_pay(args: argparse.Namespace) -> None:
    result = Lnd(args.node).pay(args.bolt11)
    if result.get("payment_error"):
        raise SystemExit(f"payment failed: {result['payment_error']}")
    print("paid, preimage " + base64.b64decode(result["payment_preimage"]).hex())


def cmd_address(args: argparse.Namespace) -> None:
    print(Core(args.wallet)("getnewaddress", "", "bech32m"))


def cmd_sign_psbt(args: argparse.Namespace) -> None:
    signed = Core(args.wallet)("walletprocesspsbt", args.psbt, True, "ALL", True, True)
    if not signed["complete"]:
        raise SystemExit("wallet could not fully sign this PSBT")
    print(signed["psbt"])
    if args.hex:
        print(signed["hex"], file=sys.stderr)


def cmd_fund_psbt(args: argparse.Namespace) -> None:
    """Pay `amount` BTC to `address` from a Core wallet as a finalized PSBT."""
    wallet = Core(args.wallet)
    created = wallet(
        "walletcreatefundedpsbt",
        [],
        [{args.address: args.amount}],
        0,
        {"fee_rate": 2, "change_type": "bech32"},
    )
    signed = wallet("walletprocesspsbt", created["psbt"], True)
    if not signed["complete"]:
        raise SystemExit("wallet could not fully sign the funding PSBT")
    print(signed["psbt"])


def cmd_web_inputs(args: argparse.Namespace) -> None:
    """Print every value the swap.html BTC->LN form asks for."""
    info = load_info()
    print("Network                 regtest")
    print(f"Relay                   {info['relay']['host']}")
    print(f"Provider identity       {info['makers']['btc-to-ln']}")
    print(f"Lightning invoice       {Lnd('user').add_invoice(args.sat, 'rill web swap')}")
    print(f"Refund address          {Core('user')('getnewaddress', '', 'bech32m')}")
    print(f"Current block height    {Core()('getblockcount')}")
    print(f"Recovery age recipient  {info['user_age_recipient']}")


def cmd_broadcast(args: argparse.Namespace) -> None:
    print(Core()("sendrawtransaction", args.tx))


def cmd_swap(args: argparse.Namespace) -> None:
    info = load_info()
    user = STATE / "user"
    work = user / "swaps" / f"{time.strftime('%Y%m%dT%H%M%S')}-{args.direction}"
    work.mkdir(mode=0o700, parents=True)
    command = [
        "rill",
        "swap",
        args.direction,
        "--network",
        str(user / "network.json"),
        "--crypto-library",
        CRYPTO,
        "--relay",
        RELAY_INTERNAL,
        "--provider",
        info["makers"][args.direction],
        "--max-success-fee-sat",
        str(args.max_fee),
        "--core-port",
        str(LOCAL_CORE_PORT),
        "--core-cookie",
        str(user / "core.cookie"),
        "--wallet",
        "user",
        "--lnd-port",
        str(LOCAL_LND_PORT),
        "--lnd-tls-cert",
        str(user / "tls.cert"),
        "--lnd-macaroon",
        str(user / "admin.macaroon"),
        "--recipient",
        info["user_age_recipient"],
        "--identity",
        str(user / "age.key"),
        "--recovery-output",
        str(work / "recovery.age"),
        "--settle-timeout",
        str(args.settle_timeout),
    ]
    if args.direction == "btc-to-ln":
        bolt11 = Lnd("user").add_invoice(args.sat, "rill dev swap")
        log(f"user invoice for {args.sat} sat: {bolt11}")
        command += ["--invoice", bolt11]
    else:
        command += ["--payout-sat", str(args.sat)]
    command += args.extra
    log(f"recovery files in {work}")
    log("running: " + " ".join(command))
    raise SystemExit(subprocess.run(command, check=False).returncode)


def main() -> None:
    parser = argparse.ArgumentParser(prog="devtool", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("bootstrap", help="idempotently prepare chain, channels and makers")
    sub.add_parser("mine-loop", help="auto-miner service loop")
    p = sub.add_parser("mine", help="mine blocks now")
    p.add_argument("blocks", type=int, nargs="?", default=1)
    p = sub.add_parser("miner", help="pause/resume the auto-miner")
    p.add_argument("action", choices=["pause", "resume", "status"])
    p = sub.add_parser("info", help="maker keys, relay URLs, height and balances")
    p.add_argument("--json", action="store_true")
    sub.add_parser("balances", help="user/maker Core wallets and LND nodes")
    p = sub.add_parser("invoice", help="create a BOLT11 invoice")
    p.add_argument("sat", type=int)
    p.add_argument("--node", choices=LND_NODES, default="user")
    p.add_argument("--memo", default="rill dev")
    p = sub.add_parser("pay", help="pay a BOLT11 invoice")
    p.add_argument("bolt11")
    p.add_argument("--node", choices=LND_NODES, default="user")
    p = sub.add_parser("address", help="new bech32m address in a Core wallet")
    p.add_argument("--wallet", choices=["user", "maker", "miner"], default="user")
    p = sub.add_parser("sign-psbt", help="sign and finalize a PSBT with a Core wallet")
    p.add_argument("psbt")
    p.add_argument("--wallet", default="user")
    p.add_argument("--hex", action="store_true", help="also print raw tx hex to stderr")
    p = sub.add_parser("fund-psbt", help="finalized PSBT paying ADDRESS the exact BTC amount")
    p.add_argument("address")
    p.add_argument("amount", help="BTC amount exactly as shown, e.g. 0.00050100")
    p.add_argument("--wallet", default="user")
    p = sub.add_parser("web-inputs", help="values for the swap.html form")
    p.add_argument("sat", type=int, nargs="?", default=50_000)
    p = sub.add_parser("broadcast", help="broadcast a raw transaction hex")
    p.add_argument("tx")
    p = sub.add_parser("swap", help="run a user swap against the local maker")
    p.add_argument("direction", choices=DIRECTIONS)
    p.add_argument("sat", type=int, nargs="?", default=50_000)
    p.add_argument("--max-fee", type=int, default=2000, help="max success fee in sat")
    p.add_argument("--settle-timeout", type=int, default=600)
    p.add_argument("extra", nargs=argparse.REMAINDER, help="extra `rill swap` flags")
    args = parser.parse_args()
    handlers = {
        "bootstrap": cmd_bootstrap,
        "mine-loop": cmd_mine_loop,
        "mine": cmd_mine,
        "miner": cmd_miner,
        "info": cmd_info,
        "balances": cmd_balances,
        "invoice": cmd_invoice,
        "pay": cmd_pay,
        "address": cmd_address,
        "sign-psbt": cmd_sign_psbt,
        "fund-psbt": cmd_fund_psbt,
        "web-inputs": cmd_web_inputs,
        "broadcast": cmd_broadcast,
        "swap": cmd_swap,
    }
    handlers[args.command](args)


if __name__ == "__main__":
    main()
