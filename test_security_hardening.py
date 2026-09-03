import argparse
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import pos_recover as p
import pos_recover_ui as ui


class CliHardeningTests(unittest.TestCase):
    def setUp(self):
        p.set_network("signet")
        self.card_priv, self.fund_priv = 1, 2
        self.card_pub = p.compress_point(p.privkey_to_point(self.card_priv))
        self.fund_pub = p.compress_point(p.privkey_to_point(self.fund_priv))
        self.card_spk = b"\x00\x14" + p.hash160(self.card_pub)
        self.fund_spk = b"\x00\x14" + p.hash160(self.fund_pub)
        self.dest = p.segwit_encode(1, bytes.fromhex("33" * 32))
        self.change = p.p2wpkh_address(self.fund_pub)

    def context(self):
        return {"network": "signet", "card": {
            "txid": "11" * 32, "vout": 0, "value": 1000,
            "scriptpubkey": self.card_spk.hex(), "spent": False,
            "confirmed": True}, "funding": {
            "txid": "22" * 32, "vout": 1, "value": 10000,
            "scriptpubkey": self.fund_spk.hex(), "spent": False,
            "confirmed": True, "address": self.change}}

    def test_fetch_writes_selected_network(self):
        args = argparse.Namespace(
            card="11" * 32 + ":0", funding="22" * 32 + ":1",
            api="https://example.invalid", no_ord=True, ord=None,
            sat=None, network="testnet4")
        utxo = {"value": 1000, "scriptpubkey": self.card_spk.hex(),
                "spent": False, "confirmed": True}
        with tempfile.TemporaryDirectory() as tmp:
            args.output = str(Path(tmp) / "context.json")
            with mock.patch.object(p, "fetch_utxo", return_value=dict(utxo)):
                p.cmd_fetch(args)
            self.assertEqual(json.loads(Path(args.output).read_text())["network"],
                             "testnet4")

    def test_context_network_must_match_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "context.json"
            path.write_text(json.dumps(self.context()))
            with self.assertRaises(p.Refusal):
                p.load_context(str(path), "mainnet")

    def test_broadcast_revalidates_exact_bytes_and_checks_remote_txid(self):
        ctx = self.context()
        plan = p.plan_recovery(ctx, self.dest, 1, change_addr=self.change)
        raw, txid, _ = p.sign_plan(
            plan, p.wif_encode(self.card_priv), p.wif_encode(self.fund_priv))
        with tempfile.TemporaryDirectory() as tmp:
            context_path = Path(tmp) / "context.json"
            tx_path = Path(tmp) / "tx.hex"
            context_path.write_text(json.dumps(ctx))
            tx_path.write_text(raw)
            args = argparse.Namespace(tx=str(tx_path), context=str(context_path),
                                      network="signet", api="https://example.invalid",
                                      yes=True)
            with mock.patch.object(p, "_http_post", return_value=txid) as post:
                p.cmd_broadcast(args)
                post.assert_called_once_with("https://example.invalid/tx", raw)

            bad_ctx = self.context()
            bad_ctx["card"]["value"] += 1
            context_path.write_text(json.dumps(bad_ctx))
            with mock.patch.object(p, "_http_post") as post:
                with self.assertRaises(SystemExit):
                    p.cmd_broadcast(args)
                post.assert_not_called()

            context_path.write_text(json.dumps(ctx))
            with mock.patch.object(p, "_http_post", return_value="00" * 32):
                with self.assertRaises(SystemExit):
                    p.cmd_broadcast(args)

            parsed = p.parse_tx(bytes.fromhex(raw))
            values = [ctx["card"]["value"], ctx["funding"]["value"]]
            scripts = [self.card_spk, self.fund_spk]
            rebuilt = p.Tx([
                p.TxIn(item["txid"], item["vout"], values[index], scripts[index],
                       item["sequence"])
                for index, item in enumerate(parsed["vin"])
            ], [p.TxOut(item["value"], item["spk"]) for item in parsed["vout"]],
               parsed["version"], parsed["locktime"])
            for index, item in enumerate(parsed["vin"]):
                rebuilt.vin[index].witness = list(item["witness"])
            rebuilt.vin[0].witness[0] = rebuilt.vin[0].witness[0][:-1] + b"\x02"
            tx_path.write_text(rebuilt.serialize().hex())
            with mock.patch.object(p, "_http_post") as post:
                with self.assertRaises(SystemExit):
                    p.cmd_broadcast(args)
                post.assert_not_called()


class UiHardeningTests(unittest.TestCase):
    def setUp(self):
        with ui.STATE_LOCK:
            ui.STATE.clear()
            ui.STATE.update(network="mainnet", network_locked=False, ctx=None,
                            wallet=None, plan=None, psbt=None, verified=None,
                            touched=time.monotonic())
            p.set_network("mainnet")

    def test_network_can_only_be_selected_once(self):
        self.assertEqual(ui.run_route(ui.network, {"network": "signet"}),
                         {"network": "signet"})
        with self.assertRaises(p.Refusal):
            ui.run_route(ui.network, {"network": "mainnet"})
        ui.reset()
        self.assertTrue(ui.STATE["network_locked"])
        self.assertEqual(ui.STATE["network"], "signet")

    def test_routes_are_serialized_across_threads(self):
        active = 0
        maximum = 0
        guard = threading.Lock()
        barrier = threading.Barrier(3)

        def operation(_):
            nonlocal active, maximum
            with guard:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.05)
            with guard:
                active -= 1

        def worker():
            barrier.wait()
            ui.run_route(operation, {})

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()
        self.assertEqual(maximum, 1)


if __name__ == "__main__":
    unittest.main()
