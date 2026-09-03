# Pos Recovery

Pos Recovery is a local Bitcoin recovery tool for moving the complete UTXO of a
Proof of Sats card to the Xverse without using any card sats to pay mining fees.

The application is designed for cards containing a rare sat at any position in
their UTXO, including the final offset. A conventional wallet sweep may consume
the last sats as fees. Pos Recovery prevents this by adding a separate Xverse
payment input.

> **Mainnet transactions are real and irreversible.** Verify the card outpoint,
> Xverse Ordinals address, funding UTXO, amounts, and final transaction before
> broadcasting. Never share the card WIF.

## How it preserves the card

For a card UTXO containing `N` sats, the transaction is fixed to this structure:

```text
Inputs
  0. Card UTXO                 N sats
  1. Xverse payment UTXO       funding sats

Outputs
  0. Xverse Ordinals address   N sats
  1. Xverse payment address    funding minus fees
```

Bitcoin's ordinal assignment is FIFO. Because output 0 has exactly the same
value as input 0, every card sat fills output 0 in its original order. The rare
sat keeps its original offset. All mining fees come from the end of input 1.

The card value is dynamic; it is not limited to 546 sats. Output 0 must remain
above the destination script's dust threshold.

## Why Xverse

Xverse is an Ordinals-aware Bitcoin wallet that separates its Ordinals address
from its payment address. Pos Recovery uses:

- the **Ordinals address** to receive the complete card UTXO;
- the **payment address** to provide the fee input and receive change.

Before starting, fund the Xverse payment address with a few thousand sats. About
5,000 to 10,000 sats generally provides a comfortable margin for the mining fee
and a change output above the dust threshold. The exact requirement depends on
the current fee rate.

Do not use an Ordinals UTXO as the funding input. Independently check that the
chosen payment UTXO contains no inscription, rune, rare sat, or other asset that
must be preserved.

## Requirements

- Python 3.8 or newer;
- the Xverse browser extension;
- the card outpoint in `TXID:VOUT` format;
- the WIF private key revealed under the card seal;
- a confirmed Xverse payment UTXO;
- internet access for blockchain queries, Xverse, and optional broadcast.

The application has no third-party Python dependencies. It uses the Python
standard library and local project code only.

## Start the application

From PowerShell or a terminal opened in the project directory:

```powershell
python pos_recover_ui.py
```

The server binds exclusively to `127.0.0.1` and opens a session-specific URL in
the default browser. If the browser does not open automatically:

```powershell
python pos_recover_ui.py --no-browser
```

Copy the complete URL printed in the terminal, including its `?t=...` session
token. Stop the application with `Ctrl+C`; sensitive in-memory state is erased.

The built-in English user guide is available from the link at the top of the
application.

## User workflow

1. **Bitcoin network** — Mainnet is selected by default. Signet is available
   under Advanced options for developers and testing. The selected network is
   locked by the server for its complete lifetime. Restart the application to
   select another network.
2. **Card** — Enter the card outpoint and WIF. The application checks the UTXO,
   confirmation status, value, script type, and key ownership.
3. **Xverse** — Connect the extension and visually verify the displayed
   Ordinals address.
4. **Funding** — Enter a confirmed UTXO belonging to the connected Xverse
   payment address and confirm that it contains no asset to preserve.
5. **Plan and card signature** — Choose the fee rate, review the exact two-input,
   two-output plan, and locally sign input 0.
6. **Xverse signature** — Xverse is requested to sign input 1 only. Automatic
   broadcast is disabled.
7. **Separate broadcast** — Review or download the verified transaction. Type
   the exact confirmation word `DIFFUSER` to broadcast the checked bytes.

## Xverse and PSBT flow

The browser uses Xverse's injected Bitcoin provider with the documented Sats
Connect methods:

- `wallet_connect`;
- `getAddresses`;
- `signPsbt`.

The signing request is equivalent to:

```javascript
signPsbt({
  psbt,
  signInputs: {
    [paymentAddress]: [1]
  },
  broadcast: false
})
```

The card WIF is never sent to Xverse. It is used by the local server to sign
input 0 with `SIGHASH_ALL`, then removed from the request object and not stored
persistently.

The Xverse response is treated as untrusted. The application reparses the PSBT
from bytes and rejects changes to the unsigned transaction, input or output
order, outpoints, amounts, scripts, sequences, version, locktime, sighash type,
UTXO metadata, or expected PSBT fields. Both ECDSA signatures are verified before
the transaction is finalized.

## Local security controls

- listens only on `127.0.0.1`;
- random session token with exact comparison;
- strict `Host` and `Origin` validation;
- request body size limit;
- nonce-based Content Security Policy;
- no CDN, remote JavaScript, fonts, CSS, or images;
- `Cache-Control: no-store` and no request-body logging;
- no cookies, `localStorage`, `sessionStorage`, or IndexedDB;
- no persistent storage of the card WIF;
- 30-minute sensitive-session expiry;
- serialized state-changing requests, preventing concurrent operations from
  interleaving shared recovery state or the engine's active network;
- a server-side network lock that cannot be reset through `/api/network` and
  remains in force when sensitive session state is erased;
- no automatic broadcast;
- exact final-byte comparison immediately before broadcast;
- remote broadcast txid must match the locally calculated txid.

Network selection is enforced across addresses, WIF, blockchain API, wallet
account, PSBT, and broadcast.

## Supported input types

- Card input: P2WPKH with a compressed WIF key;
- Xverse funding input: P2WPKH or P2SH-P2WPKH;
- Ordinals destination: P2TR;
- exactly two inputs and exactly two outputs.

Other script combinations are rejected rather than guessed.

## Tests

Run the separated PSBT and safety suite:

```powershell
python -m unittest -v test_pos_recover_psbt.py
```

Run the original cryptographic and ordinal self-tests:

```powershell
python pos_recover.py selftest
```

The automated tests cover, among other cases:

- rare sats at offsets 0 and 545;
- dynamic card values including 330, 546, 547, 1,000, and 100,000 sats;
- exact preservation of the complete card value in output 0;
- destination dust rejection;
- insufficient funding and dust change;
- invalid, non-finite, zero, negative, and excessive fee rates;
- destination/change collisions;
- truncated, mutated, duplicate, or unexpectedly extended PSBT data;
- a missing or incorrectly indexed Xverse signature;
- P2WPKH and Xverse P2SH-P2WPKH funding;
- signature verification and transaction serialization;
- Mainnet/Signet address and WIF separation.

## Validation status

The workflow has been exercised end to end with the real Xverse extension on
Signet. The confirmed Signet transaction is:

```text
ab42cffb330852c8dd680d6737a17e07fbba4317def1eed6ef158a46ee93f61c
```

That transaction confirmed the expected structure: a 1,000-sat card input at
index 0, a separate Xverse funding input at index 1, a 1,000-sat Ordinals output
at index 0, Xverse change at index 1, and fees paid entirely by funding.

The operator has also reported a successful Mainnet end-to-end recovery with a
real rare sat. The Mainnet txid and independent review evidence are not recorded
in this repository at the time of writing, so this statement should not be
treated as an external audit or universal safety guarantee.

Before publishing a release for broad use, retain evidence for:

- the confirmed Mainnet recovery and Ordinals-aware verification;
- `bitcoin-cli testmempoolaccept` where available;
- an independent code and transaction review;
- signed, immutable release artifacts and published SHA-256 hashes.

## Command-line engine

`pos_recover.py` remains available for technical operators who prefer the CLI.
Its commands include `fetch`, `build`, `verify`, `broadcast`,
`simulate`, `audit`, and `selftest`. The web application and CLI share the same
transaction, cryptographic, and ordinal-invariant engine.

Every context created by `fetch` records the selected `--network`. Subsequent
`build`, `verify`, and `broadcast` operations reject a context whose network
does not match the CLI's active `--network`.

CLI broadcast requires both the signed transaction and its original context:

```powershell
python pos_recover.py --network mainnet broadcast --tx tx.hex --context context.json
```

Immediately before sending, `broadcast` reparses the exact bytes held in memory,
revalidates both signatures and all recovery invariants against that context,
and aborts before any network request if a check fails. It then sends those same
bytes and rejects a txid response that differs from the locally calculated txid.
Running `verify` separately remains useful for review, but its previous result
is never trusted as authorization for a later broadcast.

The CLI predates the Xverse PSBT interface and may present a different two-key
workflow. Use the local web interface for the documented Xverse recovery path.

## Project files

- `pos_recover.py` — transaction, PSBT, signature, and ordinal safety engine;
- `pos_recover_ui.py` — local Xverse web interface and built-in user guide;
- `test_pos_recover_psbt.py` — separated hostile PSBT and invariant tests;
- `test_security_hardening.py` — CLI broadcast, network-context, server-lock,
  and concurrency regression tests;
- `PROCEDURE-TECHNIQUE.md` — technical rationale and manual verification;
- `PROTOCOLE-DE-TEST.md` — empirical validation protocol;
- `ARCHITECTURE-INTERFACE.md` — local-interface architecture;
- `AVERTISSEMENT-ACHETEUR.md` — card-holder warning material;
- `img/raresatscards-logo.png` — local interface logo.

## Distribution recommendations

Publish the source in a public repository and distribute versioned archives
through signed, immutable releases. Publish each archive's SHA-256 hash on the
official Rare Sats Cards website. Do not distribute private builds through
email, direct messages, or mutable “latest version” links.

The application must remain local. Do not turn the WIF workflow into a remotely
hosted web form.
