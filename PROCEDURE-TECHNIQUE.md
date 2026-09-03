# Récupération d'un satoshi Proof of Sats : procédure technique

Public visé : utilisateurs à l'aise avec Bitcoin Core, les PSBT et la théorie ordinale. Si vous cherchez la version courte, lisez `AVERTISSEMENT-ACHETEUR.md`.

Ce document décrit pourquoi un balayage standard détruit le satoshi sur une partie de la série 1, quelle construction le préserve, et comment l'exécuter sans utiliser notre script si vous préférez ne pas exécuter de binaire tiers avec votre clé privée. Cette préférence est légitime et nous la documentons en premier lieu.

## 1. Structure d'une carte

Chaque carte de la série 1 correspond à une sortie unique, non dépensée, jamais réutilisée.

```
Adresse   : P2WPKH (bech32, préfixe bc1q)
Valeur    : 546 satoshis exactement
Contenu   : 2 plages de sats
            - 1 sat du bloc 9, préfixe 450 (premier bitcoin du bloc)
            - 545 sats de padding, sans signification numismatique
Clé        : WIF compressé, imprimé sous scellé VOID
```

Exemple réel :

```
Outpoint : 47891fa0b3bc0dab093a515f29293637d5212796934f96890aa92462b2edb0fd:0
Adresse  : bc1qlrpqm8yy0xaau244jqgd5d5udjaj27ckt7ytjv
Valeur   : 546 sats
Plage 1  : 45020123482                            (sat bloc 9, offset 0)
Plage 2  : 1033044476994685 → 1033044476995229    (545 sats de padding)
```

Les clés privées de la série 1 ont été détruites après impression. Aucune correction on-chain n'est possible sur cette série.

## 2. Pourquoi un balayage standard détruit le satoshi

### La règle d'attribution ordinale

Les satoshis d'une transaction sont attribués de manière déterministe :

1. On concatène les plages de sats de toutes les entrées, dans l'ordre des entrées.
2. On remplit les sorties séquentiellement, dans l'ordre des sorties.
3. Les frais de minage sont prélevés à la toute fin de la séquence.

La conséquence tient en une phrase : le dernier satoshi de la séquence est le premier à partir au mineur.

### L'hétérogénéité du tirage

Un audit de la série 1 a révélé que la position du sat rare dans la sortie de 546 n'est pas constante. Environ la moitié des cartes l'ont à l'offset 0, environ la moitié à l'offset 545.

La cause est le tri lexicographique des entrées, BIP-69, appliqué lors des transactions de financement. Selon le txid de l'entrée portant le sat rare et celui de l'entrée de padding, l'une passait avant l'autre. Le résultat est pseudo-aléatoire, d'où la répartition à peu près égale.

### Le comportement destructeur

Considérons un balayage classique. Une entrée de 546 sats, une sortie vers l'adresse de destination, les frais prélevés sur l'unique sortie disponible.

```
Entrée 0 : carte, 546 sats
Sortie 0 : destination, 546 - frais
```

Pour une carte avec le sat à l'offset 0, la sortie contient les premiers satoshis de la séquence, dont le sat rare. Il survit, dans la plupart des configurations.

Pour une carte avec le sat à l'offset 545, la sortie contient les satoshis 0 à 545 - frais. Le sat rare, en position 545, n'y est pas. Il part au mineur.

Ce n'est pas un risque probabiliste. C'est le comportement déterministe et par défaut de tout portefeuille standard sur cette configuration. La commande suivante le démontre :

```
python3 pos_recover.py simulate
```

### Sur le test BlueWallet

Un test avec BlueWallet a réussi : import du WIF, balayage, satoshi récupéré. Ce test portait sur une carte avec le sat à l'offset 0. Il ne prouve rien pour l'autre moitié de la série, et il ne doit pas être cité comme validation de la procédure. Aucun portefeuille grand public n'est recommandé dans ce document, y compris Sparrow et Electrum, tant qu'un test n'a pas été mené sur une carte à sat en position haute avec vérification ordinale à destination.

## 3. La construction qui préserve le satoshi

Une seule construction couvre les deux configurations, sans avoir à distinguer les cas.

```
Entrée 0 : UTXO de la carte           546 sats
Entrée 1 : UTXO de financement        montant libre

Sortie 0 : adresse de destination     546 sats exactement
Sortie 1 : adresse de change          financement - frais
```

La séquence concaténée est `[carte 0→545][financement 0→n]`. La sortie 0, valant exactement 546, absorbe l'intégralité des satoshis de la carte quelle que soit la position du sat rare à l'intérieur. Les frais mordent sur la fin de l'entrée de financement, où ils ne détruisent que du padding sans valeur.

Le sat conserve son offset d'origine à destination. Une carte à l'offset 545 produit une sortie où le sat est à l'offset 545. C'est normal et sans conséquence, la sortie faisant à nouveau 546 sats.

### Les quatre invariants

Par ordre de criticité.

**INV1. L'UTXO de la carte doit être l'entrée d'index 0.** S'il passe en index 1, ses satoshis se retrouvent en fin de séquence, derrière ceux du financement, donc exposés aux frais. C'est la violation la plus dangereuse parce que la transaction reste par ailleurs valide et d'apparence normale.

**INV2. La sortie 0 doit valoir exactement 546 satoshis.** À 545, le dernier satoshi de la carte glisse vers la sortie 1, l'adresse de change. Sur une carte à sat en position haute, le satoshi rare part alors dans votre change au lieu de la destination. Récupérable, mais pas là où vous l'attendez, et invisible sur la page de vérification. À 544 ou moins, il part aux frais.

**INV3. Les frais doivent être intégralement supportés par l'entrée de financement.** Vérification équivalente et plus simple à contrôler : la valeur de la sortie 0 doit être égale à la valeur de l'entrée 0.

**INV4. Aucun réordonnancement automatique des entrées ou des sorties.** BIP-69 doit être désactivé. C'est ce tri qui a produit l'incident initial. Beaucoup de portefeuilles l'appliquent silencieusement.

### Seuils de poussière

546 satoshis passe au-dessus du seuil de relais pour tous les types de sortie courants : 294 pour P2WPKH, 330 pour P2TR et P2WSH, 546 pour P2PKH. La destination peut donc être une adresse Taproot sans difficulté. C'est le choix recommandé si vous souhaitez ensuite manipuler le sat avec des outils ordinaux.

Le change, en revanche, doit rester au-dessus de son propre seuil. Prévoyez un UTXO de financement d'au moins quelques milliers de satoshis.

## 4. Méthode de référence en bitcoin-cli

Aucun script tiers, aucune dépendance. Vous devez disposer d'un nœud avec index des transactions, et vous devez connaître les scriptPubKey et les valeurs des deux entrées.

Étape 1, construire la transaction brute. L'ordre des entrées et des sorties est celui de la ligne de commande.

```bash
bitcoin-cli createrawtransaction \
  '[{"txid":"TXID_CARTE","vout":N,"sequence":4294967295},
    {"txid":"TXID_FINANCEMENT","vout":M,"sequence":4294967295}]' \
  '[{"ADRESSE_DEST":0.00000546},{"ADRESSE_CHANGE":0.00MMMMMM}]'
```

Contrôlez immédiatement que l'ordre a été respecté, en particulier celui des sorties. Le comportement de `createrawtransaction` sur ce point a varié selon les versions de Bitcoin Core, et une sortie de destination reléguée en index 1 casse INV2.

```bash
bitcoin-cli decoderawtransaction "HEX" | jq '.vin[].txid, .vout[].value'
```

Attendu, dans cet ordre exact : txid de la carte, txid du financement, puis 0.00000546, puis le change.

Étape 2, signer.

```bash
bitcoin-cli signrawtransactionwithkey "HEX" \
  '["WIF_CARTE","WIF_FINANCEMENT"]' \
  '[{"txid":"TXID_CARTE","vout":N,"scriptPubKey":"SPK_CARTE","amount":0.00000546},
    {"txid":"TXID_FINANCEMENT","vout":M,"scriptPubKey":"SPK_FIN","amount":0.00XXXXXX}]'
```

Étape 3, contrôler avant diffusion. Ne sautez pas cette étape.

```bash
bitcoin-cli decoderawtransaction "HEX_SIGNE"
bitcoin-cli testmempoolaccept '["HEX_SIGNE"]'
```

Vérifiez à nouveau, sur la transaction signée cette fois : entrée 0 égale à l'outpoint de la carte, sortie 0 égale à exactement 546, frais égaux à la valeur du financement moins le change.

Étape 4, diffuser.

```bash
bitcoin-cli sendrawtransaction "HEX_SIGNE"
```

Si vous préférez faire relire la transaction avant de la diffuser, `decoderawtransaction` produit une sortie que vous pouvez partager sans exposer aucune clé.

## 5. Utilisation de pos-recover

Le script est en Python standard, sans aucune dépendance externe. Aucun `pip install`. Un seul fichier, lisible d'un bout à l'autre, ce qui est le minimum exigible d'un outil auquel on confie une clé privée.

Les clés ne passent jamais par la ligne de commande. Saisie masquée uniquement, donc pas d'historique shell et rien de visible dans `ps`.

Vérifiez d'abord que la cryptographie du script est correcte sur votre machine. Quarante tests, dont les vecteurs officiels RIPEMD-160 et BIP-173.

```bash
python3 pos_recover.py selftest
```

Machine en ligne, récupération des données publiques. Aucune clé n'est manipulée à cette étape.

```bash
python3 pos_recover.py fetch \
  --card 47891fa0...b0fd:0 \
  --funding aabbcc...:1 \
  --sat 45020123482 \
  -o context.json
```

Transférez `context.json` sur une machine hors ligne. Le fichier ne contient que des données publiques.

Machine hors ligne, construction et signature.

```bash
python3 pos_recover.py build \
  --context context.json \
  --dest bc1p... \
  --feerate 6 \
  -o tx.hex
```

Le script affiche un récapitulatif complet, prédit la position du sat à destination, et attend que vous tapiez `SIGNER`. Il refuse de signer si un invariant n'est pas respecté, si le WIF ne correspond pas à l'adresse de la carte, si la sortie de la carte ne vaut pas 546 satoshis, si elle est déjà dépensée, ou si la prédiction ordinale ne place pas le sat sur la sortie 0. Après signature, il réanalyse ses propres octets et revérifie tout avant d'écrire le fichier.

Contrôle indépendant, toujours hors ligne.

```bash
python3 pos_recover.py verify --tx tx.hex --context context.json
bitcoin-cli decoderawtransaction $(cat tx.hex)
```

Diffusion, étape volontairement séparée.

```bash
python3 pos_recover.py broadcast --tx tx.hex
```

## 6. Vérification après diffusion

Une transaction confirmée ne prouve pas que le satoshi est arrivé. Elle prouve que les bitcoins sont arrivés. Ce sont deux choses différentes, et c'est exactement l'erreur qui rend le test BlueWallet non concluant.

Interrogez un indexeur ordinal sur la nouvelle sortie :

```bash
curl -s https://ordinals.com/r/output/NOUVEAU_TXID:0 | jq .sat_ranges
```

Vous devez retrouver la plage contenant votre sat, à l'offset attendu. Sur une carte à sat en position haute, la plage du sat rare apparaît en fin de liste, ce qui est le comportement correct.

Vous pouvez aussi recouper avec un second indexeur, par exemple magisat.io, avant de considérer l'opération terminée. Deux indexeurs indépendants qui concordent valent mieux qu'un seul qui affirme.

## 7. État de validation

Point à traiter avec sérieux, et à ne pas retirer de cette documentation avant qu'il soit réglé.

La construction est correcte au regard de la règle ordinale, et le modèle d'attribution est vérifié par les tests du script. La cryptographie est validée sur vecteurs officiels. Ce qui n'est pas encore constaté, c'est le comportement réel de bout en bout sur mainnet.

**Test obligatoire avant publication.** Construire un UTXO témoin de 546 satoshis reproduisant exactement la structure d'une carte, avec un satoshi identifiable placé en dernière position. Exécuter la procédure complète. Vérifier sur un indexeur ordinal que le satoshi témoin est bien arrivé à l'offset 545 de la nouvelle sortie, et non dans les frais ni dans le change.

Tant que ce test n'est pas passé, considérez la procédure comme théoriquement correcte mais empiriquement non constatée.

Une remarque utile sur les modes de défaillance. Si la logique de signature du script comportait une erreur, la transaction serait rejetée par le réseau comme invalide. Rien ne bougerait, et le satoshi resterait à son adresse d'origine. Le mode de défaillance dangereux n'est pas la signature, c'est la construction, et c'est précisément ce que les invariants et le modèle ordinal contrôlent avant toute signature.

## 8. Correctif pour les séries suivantes

Le problème vient du financement, pas du produit.

Construire chaque transaction de financement manuellement, sans passer par un portefeuille. Désactiver tout tri automatique des entrées. Placer systématiquement le sat rare en offset 0 de la sortie. Vérifier chaque sortie sur un indexeur ordinal avant d'imprimer la carte correspondante, pas après.

Un sat en offset 0 est structurellement plus robuste. Il survit à un balayage imparfait, puisque les frais mordent par la fin. Cette propriété est un argument produit à part entière, et elle mérite d'être exposée sur la page de vérification de chaque carte, au même titre que le numéro du sat.

## 9. Flux PSBT avec Xverse

L'application locale construit une transaction déterministe : carte en entrée 0,
financement Xverse en entrée 1, la valeur complète `N` de l'UTXO de carte vers l'adresse
Ordinals en sortie 0, et `financement - frais` vers l'adresse de paiement en sortie 1.
La série 1 utilise `N = 546`, mais le moteur accepte toute valeur relayable. Les frais sont la fin du
flux FIFO ordinal et appartiennent ainsi entièrement au financement. Réduire la sortie 0,
même d'un sat par rapport à `N`, pourrait déplacer le dernier sat de la carte vers le change
ou les frais.

La carte est signée localement avec `SIGHASH_ALL`. La PSBT BIP-174 contient les deux
`witness_utxo`, le type de sighash et, si Xverse utilise P2SH-P2WPKH, le redeemScript.
Le navigateur demande ensuite `signPsbt` avec uniquement
`signInputs: { adressePaiement: [1] }` et `broadcast: false`.

La réponse n'est jamais présumée fidèle : le cœur reparcourt l'encodage, rejette les clés
dupliquées et métadonnées inattendues, compare la transaction non signée au plan canonique,
vérifie les deux signatures et finalise localement. La séparation signature/diffusion laisse
le temps d'exporter les octets et de les soumettre à `bitcoin-cli decoderawtransaction` et
`testmempoolaccept`. Une seconde action, accompagnée du texte exact `DIFFUSER`, reparse les
octets exacts avant envoi et compare le txid distant au txid calculé localement.

Limites actuelles : sélection manuelle de l'UTXO de paiement et confirmation explicite de
l'absence d'actifs ordinaux ; aucun indexeur ordinal signet public n'est configuré ; les
essais avec l'extension Xverse réelle et Bitcoin Core restent à exécuter et documenter.
