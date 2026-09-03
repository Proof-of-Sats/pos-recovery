# Protocole de test

Ce document décrit comment valider empiriquement la procédure de récupération avant de la publier aux détenteurs. Il se lit dans l'ordre. Chaque phase a un critère de réussite explicite et un critère d'échec qui arrête tout.

## Le piège méthodologique à éviter

Une remarque préalable qui détermine toute la conception du test.

Le script contient un modèle d'attribution ordinale. Si je construis le témoin avec ce modèle et que je vérifie le résultat avec le même modèle, un modèle erroné produirait un test qui passe. L'erreur serait cohérente avec elle-même, invisible, et validerait une procédure destructrice.

Deux règles en découlent, non négociables.

Le témoin doit être construit avec un outil indépendant du script. Bitcoin Core en ligne de commande, ou tout autre chemin qui ne partage aucun code avec `pos_recover.py`.

L'arbitre doit être un indexeur ordinal externe, jamais le script. Idéalement deux indexeurs indépendants qui concordent.

Le script est l'objet du test, pas le juge.

## Ce qui est déjà validé, et ce qui ne l'est pas

Validé par `selftest`, 49 contrôles : les vecteurs officiels RIPEMD-160, les vecteurs d'adresse BIP-173 en mainnet et signet, la dérivation secp256k1, le déterminisme et la normalisation low-S des signatures, l'aller-retour de sérialisation, le cloisonnement des réseaux, le modèle ordinal sur les deux configurations de carte, et les dix chemins de refus.

Non validé empiriquement, et c'est l'objet de ce document :

Le sighash BIP-143. Il est implémenté d'après la spécification et vérifié comme cohérent avec lui-même, mais aucun nœud Bitcoin ne l'a encore accepté. Une erreur ici produit une transaction rejetée, donc une défaillance visible et sans perte, mais elle rendrait l'outil inutilisable.

Le modèle ordinal face au comportement réel. La règle est documentée, le modèle la respecte, mais la confirmation doit venir de la chaîne.

## Phase 1. Répétition sur signet

Objectif : valider le sighash BIP-143 pour zéro satoshi de valeur réelle. C'est le test le plus rentable du protocole, et il précède tout le reste.

Le raisonnement est simple. Si une transaction construite et signée par le script est acceptée puis confirmée par le réseau signet, alors le sighash est correct, la sérialisation est correcte, le témoin de signature est correct. Ces composants sont identiques sur les deux réseaux : seuls l'encodage des adresses et l'octet de version du WIF changent, et ceux-là sont déjà couverts par les vecteurs BIP-173 dans `selftest`.

Ce que signet ne valide pas : la numérotation des satoshis. Les sats de signet n'ont aucun rapport avec ceux de mainnet, et il n'existe pas d'indexeur ordinal public pour ce réseau. La phase 1 valide la mécanique de signature, pas l'attribution ordinale.

### Procédure

Générez trois clés jetables. Pour un test signet, `os.urandom` suffit largement.

```bash
python3 - <<'EOF'
import os, pos_recover as P
P.set_network("signet")
for label in ("carte", "financement", "destination"):
    k = int.from_bytes(os.urandom(32), "big")
    pub = P.compress_point(P.privkey_to_point(k))
    print("%-13s %s  %s" % (label, P.wif_encode(k), P.p2wpkh_address(pub)))
EOF
```

Alimentez les deux premières adresses depuis un robinet signet. Il en existe plusieurs, et signet demande parfois un peu de patience. Visez 20 000 sats sur l'adresse carte et 50 000 sur l'adresse de financement.

Réduisez la sortie carte à exactement 546 satoshis. Sur signet, n'importe quel portefeuille fait l'affaire, la position du sat n'a aucune importance à cette phase. Vous pouvez aussi envoyer directement 546 satoshis depuis le robinet si son interface le permet.

Récupérez le contexte, puis construisez.

```bash
python3 pos_recover.py --network signet fetch \
  --card TXID_CARTE:VOUT --funding TXID_FIN:VOUT --no-ord -o ctx_signet.json

python3 pos_recover.py --network signet build \
  --context ctx_signet.json --dest tb1q... --feerate 2 -o tx_signet.hex

python3 pos_recover.py --network signet verify \
  --tx tx_signet.hex --context ctx_signet.json

python3 pos_recover.py --network signet broadcast \
  --tx tx_signet.hex --context ctx_signet.json
```

### Critère de réussite

La transaction est acceptée puis confirmée. Le sighash BIP-143 est validé.

### Critère d'échec

Un rejet avec un message de type `mandatory-script-verify-flag-failed` signifie que le sighash ou le témoin est incorrect. Arrêtez le protocole. Rien ne doit passer en phase 2 avant correction, et rien n'est perdu : sur signet comme sur mainnet, une signature invalide ne déplace aucun satoshi.

Un rejet pour frais insuffisants ou pour poussière n'est pas un échec de signature. Ajustez et recommencez.

## Phase 2. Le témoin mainnet

Objectif : reproduire exactement la structure d'une carte de la série 1, avec un satoshi identifiable placé en dernière position. C'est le cas destructeur, celui qui n'a jamais été testé.

### Le satoshi témoin n'a pas besoin d'être rare

Point qui réduit beaucoup le coût du test. Tout satoshi porte un numéro unique et traçable. Le témoin doit être identifiable, pas précieux. N'utilisez sous aucun prétexte un satoshi du bloc 9, ni une vraie carte.

### Construction

Vous avez besoin de deux UTXO de provenances distinctes, pour que leurs plages de sats ne soient pas contiguës et restent visuellement séparables dans la sortie de l'indexeur. Deux retraits différents, ou deux achats différents. Environ 10 000 satoshis chacun.

Appelons-les F1 et F2. Vous devez détenir leurs WIF et connaître leurs scriptPubKey.

**Étape A. Créer le padding de 545 satoshis.**

Une sortie de 545 satoshis en P2WPKH est relayable : le seuil de poussière est à 294 pour ce type. Elle passerait sous le seuil en P2PKH, à 546, donc restez en bech32.

Dépensez F1 vers une sortie 0 de 545 satoshis à destination d'une adresse P, plus un change. Utilisez `createrawtransaction`, pas un portefeuille, pour garder la main sur l'ordre.

```bash
bitcoin-cli createrawtransaction \
  '[{"txid":"F1_TXID","vout":F1_VOUT,"sequence":4294967295}]' \
  '[{"ADRESSE_P":0.00000545},{"ADRESSE_CHANGE":0.0000XXXX}]'
```

Signez, contrôlez, diffusez. Attendez la confirmation.

**Étape B. Relever le numéro du satoshi témoin.**

Interrogez l'indexeur sur F2 et notez le premier satoshi de sa première plage. C'est votre témoin, appelons-le S.

```bash
curl -s https://ordinals.com/r/output/F2_TXID:F2_VOUT | jq .sat_ranges
```

Le premier satoshi de F2 sera le premier satoshi de F2 dans la séquence concaténée. C'est ce qui rend sa position prévisible à l'étape suivante.

**Étape C. Assembler le témoin, satoshi en position haute.**

C'est le cœur du test. Deux entrées, dans cet ordre exact : le padding de 545 en index 0, F2 en index 1.

```bash
bitcoin-cli createrawtransaction \
  '[{"txid":"TXID_PADDING","vout":0,"sequence":4294967295},
    {"txid":"F2_TXID","vout":F2_VOUT,"sequence":4294967295}]' \
  '[{"ADRESSE_C":0.00000546},{"ADRESSE_CHANGE_2":0.0000XXXX}]'
```

La séquence concaténée est `[545 sats de padding][S, S+1, S+2, ...]`. La sortie 0, qui vaut 546, prend les 545 satoshis de padding puis exactement un satoshi de F2 : S. Le satoshi témoin atterrit à l'offset 545.

Contrôlez impérativement l'ordre avant de signer. Une inversion des entrées placerait S ailleurs et invaliderait le test sans que rien ne le signale.

```bash
bitcoin-cli decoderawtransaction "HEX" | jq '[.vin[].txid], [.vout[].value]'
```

Signez avec les deux WIF, contrôlez à nouveau, diffusez, attendez la confirmation.

**Étape D. Vérifier que le témoin est bien construit.**

Cette étape est un résultat en soi. Elle valide empiriquement la règle d'ordonnancement, indépendamment de mon script, avant même que celui-ci n'intervienne.

```bash
curl -s https://ordinals.com/r/output/TXID_TEMOIN:0 | jq .sat_ranges
```

Attendu : deux plages, le padding en premier, puis `[S, S+1]` en dernier. Recoupez sur magisat.io.

### Critère de réussite de la phase 2

L'indexeur montre S à l'offset 545 d'une sortie de 546 satoshis. Vous détenez une réplique fidèle du cas dangereux de la série 1.

### Critère d'échec

Si S n'est pas à l'offset 545, le modèle ordinal du document technique est faux, ou `createrawtransaction` a réordonné quelque chose. Dans les deux cas, arrêtez et corrigez la compréhension avant de continuer. C'est un échec précieux : il vaut infiniment mieux le découvrir sur un témoin que sur une carte.

## Phase 3. La récupération

Objectif : démontrer que le script préserve un satoshi en position haute.

```bash
python3 pos_recover.py fetch \
  --card TXID_TEMOIN:0 --funding TXID_CHANGE_2:VOUT --sat S -o ctx_temoin.json
```

Vérifiez à l'œil que `ctx_temoin.json` contient bien deux plages totalisant 546 satoshis, et que `target_sat` vaut S.

```bash
python3 pos_recover.py build \
  --context ctx_temoin.json --dest bc1p_ADRESSE_TAPROOT --feerate 4 -o tx_temoin.hex
```

Le récapitulatif doit annoncer `Sat S : sortie 0, offset 545 -> PRESERVE`. Si le script annonce l'offset 0, le contexte est incohérent avec ce que vous avez construit : arrêtez.

Contrôle croisé indépendant avant diffusion, celui-ci compte autant que le script.

```bash
python3 pos_recover.py verify --tx tx_temoin.hex --context ctx_temoin.json
bitcoin-cli decoderawtransaction $(cat tx_temoin.hex)
bitcoin-cli testmempoolaccept "[\"$(cat tx_temoin.hex)\"]"
```

Sur la sortie de `decoderawtransaction`, vérifiez à la main : entrée 0 égale au témoin, sortie 0 égale à exactement 0.00000546, sortie 0 payant bien l'adresse Taproot voulue.

Diffusez, attendez la confirmation, puis interrogez l'indexeur sur la nouvelle sortie.

```bash
curl -s https://ordinals.com/r/output/NOUVEAU_TXID:0 | jq .sat_ranges
```

### Critère de réussite

S apparaît à l'offset 545 de la nouvelle sortie de 546 satoshis, confirmé par deux indexeurs. La procédure est validée empiriquement sur le cas dangereux. Vous pouvez publier.

### Critère d'échec

S absent de la sortie signifie qu'il est parti aux frais ou dans le change. Cherchez-le dans la sortie 1 avant de conclure : s'il est dans votre change, l'erreur est un décalage d'un satoshi, probablement une confusion entre intervalles inclusifs et demi-ouverts. S'il est introuvable, il est parti au mineur, et le modèle est à revoir de fond en comble.

## Phase 4. Le contrôle négatif

Objectif : prouver que le problème existe, au lieu de l'affirmer.

Cette phase est facultative sur le plan technique et importante sur le plan de la crédibilité. Elle transforme un raisonnement en fait constaté, sur un forum où l'on vous demandera de démontrer plutôt que d'expliquer.

Construisez un second témoin par la phase 2, avec un satoshi témoin S2 en position haute. Puis balayez-le comme le ferait un détenteur mal informé : une seule entrée, une seule sortie, les frais prélevés dessus.

```bash
bitcoin-cli createrawtransaction \
  '[{"txid":"TXID_TEMOIN_2","vout":0}]' \
  '[{"ADRESSE_QUELCONQUE":0.00000400}]'
```

Diffusez, attendez, interrogez l'indexeur sur la sortie. S2 doit être absent. Il est parti au mineur avec les 146 satoshis de frais.

Vous obtenez alors une paire de transactions mainnet, publiques et vérifiables par n'importe qui, qui montrent le même cas de figure traité de deux façons, avec deux résultats opposés. C'est un argument que personne ne peut vous contester, et c'est aussi la meilleure justification de l'existence du produit sous forme scellée.

Notez les deux txid. Ils ont leur place dans la documentation technique publique.

## Budget et calendrier

Frais, aux taux bas d'un week-end, autour de 2 sat/vB :

| Transaction | Taille | Frais |
|---|---|---|
| A, créer le padding | environ 141 vB | environ 282 sats |
| C, assembler le témoin | environ 208 vB | environ 416 sats |
| Phase 3, la récupération | environ 221 vB | environ 442 sats |
| Phase 4, le balayage destructeur | environ 110 vB | 146 sats, dont le témoin |

Total autour de 1 300 satoshis de frais, plus environ 1 100 satoshis immobilisés dans les sorties de test, récupérables. Prévoyez 20 000 satoshis pour être tranquille, avec de la marge si les frais montent.

Calendrier : chaque étape demande une confirmation, parce que les indexeurs ordinaux n'indexent pas les transactions non confirmées. Comptez cinq confirmations en série sur mainnet pour le protocole complet, contrôle négatif inclus. Une demi-journée en pratique, à faire sur une période calme.

Faites la phase 1 sur signet d'abord, sans exception. Elle coûte du temps et pas un satoshi, et elle écarte la seule catégorie d'erreur qui pourrait vous faire perdre confiance dans l'outil au pire moment.

## Ce que le protocole ne couvre pas

À garder en tête avant de rédiger une communication publique.

Il valide la procédure sur les deux positions extrêmes, offset 0 et offset 545. L'audit des 100 cartes doit confirmer qu'aucune carte n'a son satoshi à une position intermédiaire, par exemple 300. La construction les couvrirait aussi, puisque la sortie 0 absorbe la totalité des 546 satoshis, mais la donnée doit être établie plutôt que supposée. La commande `audit` produit exactement cela.

Il ne valide aucun portefeuille grand public. Ni Sparrow, ni Electrum, ni BlueWallet. Chacun demanderait le même protocole complet, sur un témoin en position haute, avec vérification ordinale à destination. Tant que ce travail n'est pas fait, la documentation ne doit recommander aucun de ces outils, y compris ceux qui semblent permettre la construction manuelle.

Il ne dit rien du comportement des portefeuilles Taproot en aval, une fois le satoshi arrivé à destination. Un détenteur qui récupère son satoshi vers une adresse bech32m puis manipule cet UTXO avec un portefeuille non conscient des ordinaux retombe dans le même piège. Cela mérite un avertissement distinct, et cela renforce l'argument central du produit : le satoshi est plus en sécurité sur la carte que partout ailleurs.
