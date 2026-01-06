#!/usr/bin/env -S python3 -u
import atexit
import logging
import os
import signal
import subprocess
import argparse

import time
from shutil import rmtree
from subprocess import Popen, call
from typing import List

import json
import requests
import itertools
import decimal

import grpc
from retrying import retry

from admin_pb2_grpc import AdminStub
from admin_pb2 import PingRequest, ChannelNewRequest, ChannelCloseRequest, Void, InvoiceNewRequest, PaymentSendRequest, Payment, PeerConnectRequest

processes: List[Popen] = []
OUTPUT_DIR = 'test-output'
INSTANCE_OFFSET = 0  # this helps us ensure we use different ports when we run concurrent tests
NUM_PAYMENTS = 250
WAIT_TIMEOUT = 1000
CHANNEL_BALANCE_SYNC_INTERVAL = 50
CHANNEL_VALUE_SAT = 10_000_000
EXPECTED_FEE_SAT = 1458
PAYMENT_MSAT = 4_000_000  # FIXME 2_000_000 fails with dust limit policy violation
DEBUG_ON_FAIL = os.environ.get('DEBUG_ON_FAIL', '0') == '1'
USE_RELEASE_BINARIES = False
OPTIMIZATION = 'release' if USE_RELEASE_BINARIES else 'debug'
VLS_BINARIES_PATH = f'../target/{OPTIMIZATION}'
LNROD_BINARIES_PATH = f'./target/{OPTIMIZATION}'
VERBOSE = False

# options: test, vls-null, vls-grpc
SIGNER = os.environ.get("SIGNER", "vls-null")
# options: OFF, ERROR, WARN, INFO, DEBUG, TRACE
LOG_LEVEL = os.environ.get("LOG_LEVEL", "error")

logger = logging.getLogger()

os.environ['RUST_BACKTRACE'] = "1"

# we want to manage the allowlist ourselves, don't let a stray env var confuse us
os.environ.pop('ALLOWLIST', None)


def new_proc(args, log_file):
    if VERBOSE:
        return Popen(args)
    else:
        log_file = open(OUTPUT_DIR + '/' + log_file, 'w')
        return Popen(args, stdout=log_file, stderr=log_file)


def kill_all_procs(procs):
    print('Killing nodes')
    try:
        kill_procs(procs, 'nodes')
    except:
        # FIXME: Nodes should shut down cleanly
        print("Nodes didn't exit cleanly")
    print('Killing signers')
    kill_procs(procs, 'signers')
    print('Killing bitcoin')
    kill_procs(procs, 'bitcoin')


def kill_procs(processes, key):
    for p in processes[key]:
        p.send_signal(signal.SIGTERM)
    for p in processes[key]:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print(f'process {p} did not exit, killing')
            p.send_signal(signal.SIGKILL)


def stop_proc(p):
    p.send_signal(signal.SIGTERM)
    p.wait()


class BitcoindException(Exception):
    def __init__(self, error):
        self.error = error
        super().__init__()

class Bitcoind(object):
    def __init__(self, name, url, **kwargs):
        self.name = name
        self.mine_address = None
        self.url = url
        self.id_counter = itertools.count()
        super().__init__(**kwargs)

    def wait_for_ready(self):
        print("Waiting for bitcoind")
        timeout = 5
        request_exception = None
        while timeout > 0:
            try:
                self.getblockchaininfo()
                break
            except Exception as e:
                request_exception = e
                time.sleep(1)
                timeout -= 1
        if timeout <= 0:
            if request_exception:
                raise request_exception
            raise Exception('Timeout')

    def setup(self):
        print("Setting up bitcoind")
        try:
            self.createwallet('default')
        except BitcoindException as e:
            if e.error['code'] != -4:
                raise e
            print('wallet already exists, skipping creation', e)
        # unload and reload with autoload, in case dev wants to play with it later
        try:
            self.unloadwallet('default')
            # it is possible that the wallet is not loaded, so we ignore the error
        except BitcoindException as e:
            print('wallet not loaded, skipping unload')
        self.loadwallet('default', True)

    def mine(self, count=1):
        if self.mine_address is None:
            self.mine_address = self.getnewaddress()
        print(f"mine {count}")
        self.generatetoaddress(count, self.mine_address)

    def __getattr__(self, item):
        self._method_name = item
        return self

    def __call__(self, *args):
        # rpc json call
        method_name = self._method_name
        del self._method_name
        playload = json.dumps({'jsonrpc': '2.0', 'id': next(self.id_counter), "method": method_name, "params": args})
        headers = {'Content-type': 'application/json'}
        resp = None
        try:
            resp = requests.post(self.url, headers=headers, data=playload, timeout=30)
            resp = resp.json(parse_float=decimal.Decimal)
        except Exception as e:
            error_msg = resp.text if resp is not None else e
            msg = u"{} {}:[{}] \n {}".format('post', method_name, args, error_msg)
            logger.error(msg)
            raise e

        if resp.get('error') is not None:
            e = resp['error']
            logger.error('{}:[{}]\n {}:{}'.format(method_name, args, e['code'], e['message']))
            raise BitcoindException(e)
        elif 'result' not in resp:
            logger.error('[{}]:[{}]\n MISSING JSON-RPC RESULT'.format(method_name, args, ))
            raise Exception('missing result')

        return resp['result']

@retry(stop_max_attempt_number=10, wait_fixed=500)
def grpc_client(url):
    channel = grpc.insecure_channel(url)
    stub = AdminStub(channel)
    stub.Ping(PingRequest(message="hello"), timeout=1)
    return stub


# retry every 0.1 seconds until WAIT_TIMEOUT seconds have passed
def wait_until(name, func):
    logger.debug(f'wait for {name}')
    timeout = WAIT_TIMEOUT * 10
    exc = None
    while timeout > 0:
        try:
            if func():
                break
        except Exception as e:
            exc = e
        time.sleep(0.1)
        timeout -= 1
    if timeout <= 0:
        if DEBUG_ON_FAIL:
            print(f'failed with exc={exc}')
            import pdb; pdb.set_trace()
        if exc:
            raise exc
        raise Exception(f'Timeout waiting for {name}')
    logger.debug(f'done {name}')


def run(disaster_recovery_block_explorer, existing_bitcoin_rpc):
    # ensure we sync after the last payment
    assert NUM_PAYMENTS % CHANNEL_BALANCE_SYNC_INTERVAL == 0
    assert disaster_recovery_block_explorer is None or SIGNER == 'vls-grpc', "test_disaster only works with vls-grpc"

    procs = {'nodes': [], 'signers': [], 'bitcoin': []}

    # Stop the processes in the reverse order they were started
    atexit.register(lambda: kill_all_procs(procs))

    rmtree(OUTPUT_DIR, ignore_errors=True)
    os.mkdir(OUTPUT_DIR)

    if existing_bitcoin_rpc:
        print('Connecting to bitcoind')
        btc = connect_bitcoind(existing_bitcoin_rpc)
        bitcoin_rpc = existing_bitcoin_rpc + "/wallet/default"
    else:
        btc, _ = start_bitcoind(procs)
        # TODO: we have to use 127.0.0.1 instead of localhost because
        # of a bug in the jsonrpc library which doesn't try all the
        # resolved addresses when the first fails
        bitcoin_rpc = 'http://user:pass@127.0.0.1:18443/wallet/default'

    print('Starting nodes')
    alice, _, _ = start_node(1, bitcoin_rpc, procs)
    bob, _, _ = start_node(2, bitcoin_rpc, procs)
    charlie, charlie_proc, charlie_proc1 = start_node(3, bitcoin_rpc, procs)

    print('Generate initial blocks')
    btc.mine(110)
    balance = btc.getbalance()
    assert balance > 0

    time.sleep(5)
    print("at height", btc.getblockchaininfo()['blocks'])

    alice_id = alice.NodeInfo(Void()).node_id
    bob_id = bob.NodeInfo(Void()).node_id
    charlie_id = charlie.NodeInfo(Void()).node_id

    print('Create channel alice -> bob')
    try:
        alice.PeerConnect(PeerConnectRequest(node_id=bob_id, address=f'127.0.0.1:{bob.lnport}'))
        alice.ChannelNew(ChannelNewRequest(node_id=bob_id, value_sat=CHANNEL_VALUE_SAT, is_public=True))
    except Exception as e:
        print(e)
        time.sleep(10000)
        raise

    # we have to wait here to prevent a race condition on the bitcoin wallet UTXOs
    # TODO UTXO locking
    wait_until('channel at bob', lambda: bob.ChannelList(Void()).channels[0].is_pending)
    wait_until('channel at alice', lambda: alice.ChannelList(Void()).channels[0].is_pending)

    btc.mine(1)
    time.sleep(1)
    btc.mine(1)

    print('Create channel bob -> charlie')
    try:
        bob.PeerConnect(PeerConnectRequest(node_id=charlie_id, address=f'127.0.0.1:{charlie.lnport}'))
        bob.ChannelNew(ChannelNewRequest(node_id=charlie_id, value_sat=CHANNEL_VALUE_SAT, is_public=True))
    except Exception as e:
        print(e)
        raise

    wait_until('channel at charlie', lambda: charlie.ChannelList(Void()).channels[0].is_pending)

    btc.mine(6)

    def channel_active():
        btc.mine(1)
        alice_chans = alice.ChannelList(Void())
        bob_chans = bob.ChannelList(Void())
        charlie_chans = charlie.ChannelList(Void())
        return (not alice_chans.channels[0].is_pending and
                not bob_chans.channels[0].is_pending and
                not bob_chans.channels[1].is_pending and
                not charlie_chans.channels[0].is_pending and
                alice_chans.channels[0].is_active and
                bob_chans.channels[0].is_active and
                bob_chans.channels[1].is_active and
                charlie_chans.channels[0].is_active)

    wait_until('active at both', channel_active)

    time.sleep(5)
    print("at height", btc.getblockchaininfo()['blocks'])

    def best_block_sync(node):
        return node.NodeInfo(Void()).best_block_hash[::-1].hex() == btc.getblockchaininfo()['bestblockhash']

    wait_until('alice synced', lambda: best_block_sync(alice))
    wait_until('bob synced', lambda: best_block_sync(bob))
    wait_until('charlie synced', lambda: best_block_sync(charlie))

    assert alice.ChannelList(Void()).channels[0].is_active
    assert bob.ChannelList(Void()).channels[0].is_active

    print(f'Alice initial balance {alice.ChannelList(Void()).channels[0].outbound_msat}')
    print(PAYMENT_MSAT * CHANNEL_BALANCE_SYNC_INTERVAL)

    time.sleep(5)
    print("at height", btc.getblockchaininfo()['blocks'])

    for i in range(1, NUM_PAYMENTS + 1):
        print(f'Pay invoice {i}')
        invoice = charlie.InvoiceNew(InvoiceNewRequest(value_msat=PAYMENT_MSAT)).invoice
        alice.PaymentSend(PaymentSendRequest(invoice=invoice))

        if i % CHANNEL_BALANCE_SYNC_INTERVAL == 0:
            def check_payments():
                payments = alice.PaymentList(Void()).payments
                assert len(payments) == i
                return all(p.status == Payment.PaymentStatus.Succeeded for p in payments)

            print('*** SYNC TO PAYMENT STATUS')
            wait_until('payments succeed', check_payments)

            print('*** CHECK CHANNEL BALANCE')

            wait_until('channel balance alice',
                       lambda: assert_equal_delta(CHANNEL_VALUE_SAT * 1000 - EXPECTED_FEE_SAT * 1000 - alice.ChannelList(Void()).channels[0].outbound_msat,
                                                  i * PAYMENT_MSAT))
            wait_until('channel balance charlie',
                       lambda: assert_equal_delta(charlie.ChannelList(Void()).channels[0].outbound_msat,
                                                  max(0, i * PAYMENT_MSAT)))

    def wait_received(node_id, minimum=1):
        btc.mine(2)
        return get_swept_value(node_id) >= minimum

    def get_swept_value(node_id):
        return int(btc.getreceivedbylabel(f'sweep-{node_id.hex()}') * 100000000)

    print('Closing alice - bob')
    alice_channel = alice.ChannelList(Void()).channels[0]
    alice.ChannelClose(ChannelCloseRequest(channel_id=alice_channel.channel_id))

    wait_until('alice sweep', lambda: wait_received(alice_id))
    wait_until('bob sweep', lambda: wait_received(bob_id))
    alice_sweep = int(get_swept_value(alice_id))
    bob_sweep = int(get_swept_value(bob_id))
    assert_equal_delta(CHANNEL_VALUE_SAT - (NUM_PAYMENTS * PAYMENT_MSAT) / 1000 - 1000, alice_sweep)
    assert_equal_delta((NUM_PAYMENTS * PAYMENT_MSAT) / 1000 - 1000, bob_sweep)

    if disaster_recovery_block_explorer is not None:
        utxos = fund_vls_addresses(btc, vls_port=6600 + INSTANCE_OFFSET + 3, count=2, amount=0.01)

        print('Disaster recovery at charlie')
        stop_proc(charlie_proc)
        stop_proc(charlie_proc1)
        destination = btc.getnewaddress(f"sweep-{charlie_id.hex()}")
        vlsd = VLS_BINARIES_PATH + '/vlsd'
        if disaster_recovery_block_explorer == 'bitcoind':
            recover_rpc = bitcoin_rpc
            recover_type = 'bitcoind'
        elif disaster_recovery_block_explorer == 'esplora':
            recover_rpc = 'http://localhost:8094/regtest/api/'
            recover_type = 'esplora'
        else:
            raise ValueError(f'Unknown block explorer {disaster_recovery_block_explorer}')

        input_utxo = format_input_utxo(utxos[0])
        input_utxo2 = format_input_utxo(utxos[1])
        fee_rate = 100

        p = call([vlsd,
                  '--network=regtest',
                  '--datadir', f'{OUTPUT_DIR}/vls3',
                  '--recover-type', recover_type,
                  '--recover-rpc', recover_rpc,
                  '--recover-to', destination,
                  '--fee-rate', str(fee_rate),
                  '--input-utxo', input_utxo])
        assert p == 0
        print('Sweep at charlie')
        btc.mine(145)
        # wait for Charlie to see the mined blocks
        time.sleep(5)

        p = call([vlsd,
                  '--network=regtest',
                  '--datadir', f'{OUTPUT_DIR}/vls3',
                  '--recover-type', recover_type,
                  '--recover-rpc', recover_rpc,
                  '--recover-to', destination,
                  '--fee-rate', str(fee_rate),
                  '--input-utxo', input_utxo2])
        assert p == 0
        print('Swept at charlie')
    else:
        print('Force closing bob - charlie at charlie')
        charlie_channel = charlie.ChannelList(Void()).channels[0]
        charlie.ChannelClose(ChannelCloseRequest(channel_id=charlie_channel.channel_id, is_force=True))
        wait_until('bob sweep', lambda: wait_received(bob_id, minimum=bob_sweep + 1))
        bob_sweep = int(get_swept_value(bob_id))
        # bob, as router, is flat except for fees
        assert_equal_delta(CHANNEL_VALUE_SAT - 2000, bob_sweep)

        # charlie should not have been able to sweep yet
        charlie_sweep = int(get_swept_value(charlie_id))
        assert charlie_sweep == 0

    # charlie eventually sweeps their payments
    wait_until('charlie sweep', lambda: wait_received(charlie_id))
    charlie_sweep = int(get_swept_value(charlie_id))
    assert_equal_delta((NUM_PAYMENTS * PAYMENT_MSAT) / 1000 - 1000, charlie_sweep)

    print('Done')


def assert_equal_delta(a, b):
    if a < b * 0.995 or a > b * 1.005:
        raise AssertionError(f'value out of range {a} vs {b}')
    return True


def start_bitcoind(procs):
    print("Starting bitcoind")

    popen_args = [
        # 'strace', '-o', '/tmp/out', '-s', '10000', '-f',
        'bitcoind', '--regtest', '--fallbackfee=0.0000001',
        '--rpcuser=user', '--rpcpassword=pass',
        # '--debug=rpc',
        f'--datadir={OUTPUT_DIR}']
    btc_proc = new_proc(popen_args, 'btc.log')
    procs['bitcoin'].append(btc_proc)
    btc = Bitcoind('btc-regtest', 'http://user:pass@localhost:18443')
    time.sleep(2)
    btc.wait_for_ready()
    btc.setup()
    btc = Bitcoind('btc-regtest', 'http://user:pass@localhost:18443/wallet/default')
    return btc, btc_proc


def connect_bitcoind(bitcoin_rpc):
    btc = Bitcoind('btc-regtest', bitcoin_rpc)
    btc.wait_for_ready()
    btc.setup()
    btc = Bitcoind('btc-regtest', bitcoin_rpc + '/wallet/default')
    return btc


def format_input_utxo(utxo: dict) -> str:
    """
    Format a UTXO for vlsd --input-utxo CLI argument.

    Expected keys:
      - txid
      - vout
      - amount (BTC)
      - path (derivation path)
    """
    value_sats = int(utxo["amount"] * 100_000_000)
    return f"{utxo['txid']}:{utxo['vout']}:{value_sats}:{utxo['path']}"


def fund_vls_addresses(btc: Bitcoind, vls_port: int, amounts: List[float] = None, count: int = 1, amount: float = None):
    """
    Fund VLS-controlled addresses.

    Gets addresses from VLS and sends bitcoin to them, returning the resulting UTXOs.

    - If `amounts` is provided, funds one address for each amount in the list.
    - If `count` and `amount` are provided, funds `count` addresses each with `amount`.
    """

    if amounts is None:
        if amount is None:
            raise ValueError("Must provide either `amounts` list or (`count` + `amount`).")
        amounts = [amount] * count

    result = run_vls_cli_command(
        vls_port,
        ["addresses", "list", "--count", str(len(amounts))]
    )
    addresses = json.loads(result.stdout)["addresses"]

    utxos = []
    for addr_info, amt in zip(addresses, amounts):
        address = addr_info["address"]
        txid = btc.sendtoaddress(address, amt)
        btc.mine(1)

        tx = btc.gettransaction(txid)
        vout = None

        for detail in tx.get("details", []):
            if detail.get("address") == address and detail.get("category") == "send":
                vout = detail.get("vout")
                break

        if vout is None:
            raise ValueError(f"Could not find vout for address {address} in transaction {txid}")

        utxos.append({
            **addr_info,
            "txid": txid,
            "vout": vout,
            "amount": amt,
        })

    return utxos


def run_vls_cli_command(port: int, args: List[str]) -> subprocess.CompletedProcess:
    rpc_uri = f"--rpc-uri=http://127.0.0.1:{port}"
    full_args = [
        f"{VLS_BINARIES_PATH}/vls-cli",
        "--rpc-user=vls",
        "--rpc-password=bitcoin",
        rpc_uri,
    ] + args
    try:
        result = subprocess.run(
            full_args,
            capture_output=True,
            text=True,
            check=True,
        )
        return result
    except subprocess.CalledProcessError as e:
        raise Exception(f"vls-cli command failed: {e.stderr}") from e


def start_vlsd(n, procs):
    print("Starting signer for node", n)

    vlsd = VLS_BINARIES_PATH + '/vlsd'
    popen_args = [vlsd,
                  '--log-level', LOG_LEVEL.lower(),
                  '--network=regtest',
                  '--policy-filter=policy-commitment-htlc-routing-balance:warn',  # FIXME we need add_invoice on vlsd
                  '--datadir', f'{OUTPUT_DIR}/vls{n}',
                  '--rpc-server-port', str(6600 + INSTANCE_OFFSET + n),
                  '--connect', f"http://127.0.0.1:{str(7700 + INSTANCE_OFFSET + n)}",
                  '--rpc-user=vls',
                  '--rpc-pass=bitcoin']
    p = new_proc(popen_args, f'vlsd{n}.log')
    procs['signers'].append(p)
    time.sleep(1)
    return p


def start_node(n, bitcoin_rpc, procs):
    print('Starting node', n)

    lnrod = LNROD_BINARIES_PATH + '/lnrod'
    popen_args = ([lnrod,
                   '--log-level-console', LOG_LEVEL.upper(),
                   '--regtest',
                   '--datadir', f'{OUTPUT_DIR}/data{n}',
                   '--signer', SIGNER,
                   '--vlsport', str(7700 + INSTANCE_OFFSET + n),
                   '--rpcport', str(8800 + INSTANCE_OFFSET + n),
                   '--lnport', str(9900 + INSTANCE_OFFSET + n),
                   '--bitcoin', bitcoin_rpc])
    p = new_proc(popen_args, f'node{n}.log')
    procs['nodes'].append(p)
    time.sleep(2)  # FIXME allow gRPC to function before signer connects so we can ping instead of randomly waiting
    p2 = None
    if SIGNER == 'vls-grpc':
        p2 = start_vlsd(n, procs)

    print("Starting gRPC client")
    lnrod = grpc_client(f'localhost:{8800 + INSTANCE_OFFSET + n}')
    lnrod.lnport = 9900 + INSTANCE_OFFSET + n
    return lnrod, p, p2

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-disaster", help=f"test disaster recovery, with choice of block explorer / bitcoind",
                        choices=['bitcoind', 'esplora'])
    parser.add_argument("--bitcoin", help="bitcoin RPC to use instead of starting a new one, e.g. http://user:pass@localhost:18443")
    parser.add_argument("--instance", help="offset ports for concurrent runs", type=int, default=0)
    parser.add_argument("-v", "--verbose", help=f"show stdout and stderr from subprocesses", action="store_true")
    args = parser.parse_args()
    VERBOSE = args.verbose
    INSTANCE_OFFSET = args.instance * 10
    run(disaster_recovery_block_explorer=args.test_disaster, existing_bitcoin_rpc=args.bitcoin)
