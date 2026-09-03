import base64
import math
import unittest

import pos_recover as p


class PsbtSafetyTests(unittest.TestCase):
    def setUp(self):
        p.set_network("signet")
        self.card_priv, self.fund_priv = 1, 2
        self.card_pub = p.compress_point(p.privkey_to_point(self.card_priv))
        self.fund_pub = p.compress_point(p.privkey_to_point(self.fund_priv))
        self.card_spk = bytes.fromhex("0014") + p.hash160(self.card_pub)
        self.fund_spk = bytes.fromhex("0014") + p.hash160(self.fund_pub)
        self.dest = p.segwit_encode(1, bytes.fromhex("33" * 32))
        self.change = p.p2wpkh_address(self.fund_pub)

    def context(self, offset=545, fund_value=10000, card_value=546):
        start = 100000
        if offset >= card_value:
            offset = card_value - 1
        return {"network":"signet", "card":{
            "txid":"11"*32,"vout":0,"value":card_value,"scriptpubkey":self.card_spk.hex(),
            "spent":False,"confirmed":True,"sat_ranges":[[start,start+card_value]],
            "target_sat":start+offset}, "funding":{
            "txid":"22"*32,"vout":1,"value":fund_value,"scriptpubkey":self.fund_spk.hex(),
            "address":self.change,"spent":False,"confirmed":True,"public_key":self.fund_pub.hex()}}

    def signed_by_wallet(self, original, plan, index=1, sighash=p.SIGHASH_ALL):
        parsed = p.parse_psbt(original)
        tx = plan["tx"]
        digest = tx.sighash_p2wpkh(index)
        r, s = p.ecdsa_sign(self.fund_priv, digest)
        sig = p.der_encode(r, s) + bytes([sighash])
        maps = [list(x) for x in parsed["inputs"]]
        maps[index].append((b"\x02" + self.fund_pub, sig))
        return p.serialize_psbt(parsed["unsigned"], maps, parsed["outputs"])

    def test_offsets_zero_and_545_remain_in_output_zero(self):
        for offset in (0, 545):
            plan = p.plan_recovery(self.context(offset), self.dest, 5, change_addr=self.change)
            self.assertEqual(plan["prediction"], {"output":0,"offset":offset})
            self.assertEqual(plan["tx"].vout[0].value, 546)

    def test_card_value_is_dynamic_and_preserved_exactly(self):
        for value in (330, 547, 1000, 100000):
            plan = p.plan_recovery(self.context(offset=value-1, card_value=value),
                                   self.dest, 5, change_addr=self.change)
            self.assertEqual(plan["card_value"], value)
            self.assertEqual(plan["tx"].vin[0].value, value)
            self.assertEqual(plan["tx"].vout[0].value, value)
            self.assertEqual(plan["prediction"], {"output":0, "offset":value-1})

    def test_dynamic_card_output_below_destination_dust_is_rejected(self):
        with self.assertRaises(p.Refusal):
            p.plan_recovery(self.context(card_value=329), self.dest, 5,
                            change_addr=self.change)

    def test_fee_rate_rejects_non_finite_zero_negative_and_excessive(self):
        for rate in (math.nan, math.inf, -math.inf, 0, -1, p.MAX_FEERATE + 1):
            with self.assertRaises(p.Refusal):
                p.plan_recovery(self.context(), self.dest, rate, change_addr=self.change)

    def test_insufficient_funding_and_dust_are_rejected(self):
        with self.assertRaises(p.Refusal):
            p.plan_recovery(self.context(fund_value=100), self.dest, 5, change_addr=self.change)

    def test_destination_equals_change_rejected(self):
        with self.assertRaises(p.Refusal):
            p.plan_recovery(self.context(), self.change, 5, change_addr=self.change)

    def test_psbt_round_trip_and_two_signatures(self):
        plan = p.plan_recovery(self.context(), self.dest, 5, change_addr=self.change)
        original = p.create_card_signed_psbt(plan, p.wif_encode(self.card_priv), self.fund_pub.hex())
        returned = self.signed_by_wallet(original, plan)
        result = p.verify_xverse_psbt(original, returned, plan, self.fund_pub.hex())
        self.assertEqual(len(bytes.fromhex(result["txid"])), 32)
        self.assertGreater(result["vsize"], 0)
        tx = p.parse_tx(bytes.fromhex(result["hex"]))
        self.assertEqual([o["value"] for o in tx["vout"]], [546, plan["change_value"]])

    def test_xverse_p2sh_p2wpkh_funding_key_matches(self):
        redeem = b"\x00\x14" + p.hash160(self.fund_pub)
        p2sh_spk = b"\xa9\x14" + p.hash160(redeem) + b"\x87"
        ctx = self.context()
        ctx["funding"]["scriptpubkey"] = p2sh_spk.hex()
        ctx["funding"]["address"] = p.b58check_encode(
            bytes([p._NET["p2sh"]]) + p.hash160(redeem))
        plan = p.plan_recovery(ctx, self.dest, 1,
                               change_addr=ctx["funding"]["address"])
        original = p.create_card_signed_psbt(
            plan, p.wif_encode(self.card_priv), self.fund_pub.hex())
        self.assertEqual(dict(p.parse_psbt(original)["inputs"][1])[b"\x04"], redeem)

    def test_wallet_signature_on_wrong_index_is_rejected(self):
        plan = p.plan_recovery(self.context(), self.dest, 5, change_addr=self.change)
        original = p.create_card_signed_psbt(plan, p.wif_encode(self.card_priv), self.fund_pub.hex())
        with self.assertRaises(p.Refusal):
            p.verify_xverse_psbt(original, self.signed_by_wallet(original, plan, 0), plan, self.fund_pub.hex())

    def test_unsigned_transaction_mutation_is_rejected(self):
        plan = p.plan_recovery(self.context(), self.dest, 5, change_addr=self.change)
        original = p.create_card_signed_psbt(plan, p.wif_encode(self.card_priv), self.fund_pub.hex())
        returned = p.parse_psbt(self.signed_by_wallet(original, plan))
        changed = bytearray(returned["unsigned"]); changed[-5] ^= 1
        mutant = p.serialize_psbt(bytes(changed), returned["inputs"], returned["outputs"])
        with self.assertRaises(p.Refusal):
            p.verify_xverse_psbt(original, mutant, plan, self.fund_pub.hex())

    def test_truncated_duplicate_and_unexpected_psbt_data_rejected(self):
        plan = p.plan_recovery(self.context(), self.dest, 5, change_addr=self.change)
        original = p.create_card_signed_psbt(plan, p.wif_encode(self.card_priv), self.fund_pub.hex())
        with self.assertRaises(ValueError): p.parse_psbt(base64.b64encode(base64.b64decode(original)[:-1]).decode())
        parsed = p.parse_psbt(original); maps=[list(x) for x in parsed["inputs"]]
        maps[1].append((b"\xfcunknown", b"x"))
        bad = p.serialize_psbt(parsed["unsigned"], maps, parsed["outputs"])
        returned = self.signed_by_wallet(bad, plan)
        with self.assertRaises(p.Refusal): p.verify_xverse_psbt(original, returned, plan, self.fund_pub.hex())


if __name__ == "__main__":
    unittest.main()
