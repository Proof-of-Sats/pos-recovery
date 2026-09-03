#!/usr/bin/env python3
"""Génère localement une paire mainnet jetable compatible avec les cartes."""
import secrets
import sys

import pos_recover as core


def main():
    if not sys.stdin.isatty():
        raise SystemExit("Exécution dans un terminal interactif requise.")
    print("ATTENTION : clé MAINNET réelle.")
    print("Ne la copiez dans aucun chat, e-mail, cloud ou capture d'écran.")
    confirmation = input("Tapez GENERER pour continuer : ")
    if confirmation != "GENERER":
        raise SystemExit("Annulé ; aucune clé générée.")

    core.set_network("mainnet")
    private_key = secrets.randbelow(core._N - 1) + 1
    public_key = core.compress_point(core.privkey_to_point(private_key))
    print("\nADRESSE=" + core.p2wpkh_address(public_key))
    print("WIF=" + core.wif_encode(private_key, True))
    print("\nNotez ces informations hors ligne puis fermez ce terminal.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
