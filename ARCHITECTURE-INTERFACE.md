# Interface : pourquoi local, et pourquoi pas une application

Note de décision. Elle explique un choix qui a l'air d'un compromis technique et qui est en réalité un choix de positionnement.

## Le tool en ligne est disqualifié

Pas par prudence excessive. Par arithmétique.

Un outil de signature hébergé demande à l'utilisateur de saisir une clé privée dans une page web. Même si le JavaScript est entièrement côté client et ne transmet rien, cette page est servie par un serveur, à travers un DNS, sous un certificat. Trois points de contrôle dont aucun ne vous appartient entièrement. Quiconque en prend un seul peut remplacer le script par une version qui exfiltre la clé, et l'utilisateur ne verra aucune différence : même URL, même cadenas, même interface.

Ce n'est pas un scénario théorique. MyEtherWallet a perdu des fonds par détournement DNS en 2018, Copay a distribué une dépendance npm compromise la même année, et la liste des portefeuilles web vidés par substitution de script est longue. Le mode de défaillance est toujours le même : le code est correct le jour de l'audit et différent le jour du vol.

Il y a un problème supplémentaire, propre à ta situation. Un domaine officiel qui demande une clé privée entraîne tes détenteurs à considérer ce geste comme normal. Le jour où quelqu'un enregistre `recover-raresatscards.com` et copie ta page, tu as toi-même construit la crédulité qui rend l'attaque rentable. Ta documentation dit à l'acheteur de ne jamais saisir sa clé dans un navigateur connecté. Un outil hébergé contredirait ta propre consigne de sécurité, et cette contradiction est plus coûteuse que l'inconfort qu'elle prétend résoudre.

Ajoutons que raresatscards.com est sur Shopify. Y héberger un outil de signature n'est de toute façon pas sérieux.

## L'application packagée est le pire rapport coût-bénéfice

C'est l'option qui a l'air professionnelle et qui échoue sur ton public précis.

Un binaire est inauditable. Un Bitcoiner expérimenté qui reçoit une carte à quelques centaines d'euros ne va pas exécuter un exécutable non signé qui réclame sa clé privée, et il aura raison. Tu perdrais exactement le segment dont l'avis compte le plus, celui qui parle sur Bitcointalk et sur X.

Le coût est réel par ailleurs. Trois plateformes à construire et à tester, un certificat de signature de code Windows, une notarisation Apple avec compte développeur, une chaîne de publication à maintenir à chaque version, et la question de la mise à jour qui devient une surface d'attaque de plus. Pour une série de cent cartes dont la plupart des détenteurs ne feront jamais l'opération.

Tu paierais cher pour un objet moins crédible que ce que tu as déjà.

## La voie retenue : une interface servie par le script lui-même

`pos_recover_ui.py` démarre un serveur sur 127.0.0.1, ouvre le navigateur, et sert un assistant en six étapes. À la fermeture du programme, il ne reste rien.

Ce que ça règle d'un coup.

Aucune installation, aucune dépendance, aucun paquet. Deux fichiers Python et un interpréteur déjà présent sur macOS et Linux, à installer en une fois sur Windows.

L'interface est un navigateur, donc familière de tout le monde, sans avoir à construire une application.

La page ne charge aucune ressource externe. Ni police, ni feuille de style, ni script distant. Elle fonctionne sur une machine sans réseau, ce qui est précisément le mode d'usage recommandé pour la partie signature.

Le code reste auditable. L'interface ne contient aucune cryptographie : elle appelle `pos_recover.py`, qui se lit seul. Un Bitcoiner qui se méfie de l'interface peut supprimer le fichier et utiliser la ligne de commande. Les deux chemins traversent le même code, `plan_recovery` puis `sign_plan`, donc les mêmes refus s'appliquent des deux côtés. Il n'y a pas de version simplifiée et moins sûre pour les débutants.

Tu ne distribues pas de binaire, donc pas de certificat, pas de notarisation, pas de chaîne de mise à jour à sécuriser.

### Le partage en ligne et hors ligne

L'architecture honnête sépare selon ce que la donnée exige, pas selon ce qui est commode.

En ligne, et sans aucun risque : la consultation de la carte, la position du satoshi, l'état de la sortie, la préparation du contexte, la diffusion de la transaction signée. Ce sont des données publiques et des octets déjà signés. C'est ce que fait déjà `verify.raresatscards.com`, et c'est là que doit vivre tout ce qui est pédagogique.

Local uniquement : la clé, la construction, la signature.

Cette frontière donne aussi le bon découpage produit. La page de vérification en ligne peut absorber tout le travail d'explication et de dissuasion, et ne renvoyer vers l'outil local que le petit nombre de détenteurs qui iront jusqu'au bout.

## Ce que l'interface fait, dans l'ordre

Six étapes, numérotées parce qu'il s'agit d'une séquence réellement irréversible.

**01. La carte.** Saisie de la sortie, consultation de la chaîne, affichage du numéro du satoshi et de sa position. Deux réglettes de 546 unités montrent côte à côte ce qu'un portefeuille standard ferait et ce que l'outil fait. Sur une carte à satoshi en position haute, le repère passe au rouge dans la zone prélevée par le mineur. C'est le seul endroit de tout le projet où le risque devient visible en une seconde plutôt qu'explicable en trois paragraphes.

Cette étape se termine sur un rappel que le satoshi ne risque rien si l'utilisateur s'arrête là, et sur deux boutons dont le premier est « Ne rien faire ».

**02. Les frais.** L'outil génère lui-même une adresse temporaire et demande d'y envoyer quelques milliers de satoshis. C'est le déblocage d'usage le plus important de toute l'interface : l'obstacle réel n'était pas la signature, c'était d'exiger d'un collectionneur qu'il exporte une clé privée depuis un portefeuille pour financer les frais. Personne de non technique ne sait faire ça. Envoyer des satoshis à une adresse affichée, tout le monde sait.

L'adresse est jetable. Le reliquat repart vers le portefeuille de l'utilisateur à l'étape suivante, donc il n'a aucune clé à conserver.

**03. Les destinations.** Deux adresses, obligatoirement distinctes. Une règle de sûreté est apparue en concevant cette étape et a été ajoutée au cœur : si le satoshi et la monnaie arrivaient à la même adresse, un portefeuille qui dépense depuis cette adresse pourrait consolider les deux sorties et détruire le satoshi. L'outil refuse.

**04. Le plan.** Récapitulatif complet, sans qu'aucune clé n'ait encore été saisie. C'est le bénéfice du découpage `plan_recovery` / `sign_plan` : l'utilisateur voit exactement ce qui va se passer avant d'ouvrir le scellé. Le bouton qui mène à l'étape suivante est le seul de l'interface en rouge, et il porte le nom de l'acte réel, « Ouvrir le scellé », pas « Continuer ».

**05. La clé.** Champ masqué, vidé après usage. Signature locale.

**06. La diffusion.** Transaction signée affichée, enregistrable, diffusable en une action séparée. Le message final rappelle qu'une confirmation prouve l'arrivée des bitcoins et pas celle du satoshi, et qu'il faut vérifier sur un indexeur.

## Ce qui manque encore

Un QR code pour l'adresse de frais, afin de payer depuis un téléphone sans recopier. Une implémentation en Python pur représente environ deux cents lignes, sans dépendance possible puisque la page doit rester autonome. À faire.

Le mode deux machines n'est pas encore guidé dans l'interface. Aujourd'hui le parcours suppose une machine unique avec accès réseau, ce qui est le compromis raisonnable pour une carte de cette valeur, le risque principal étant un logiciel malveillant local. Pour les cartes à forte valeur, ou pour un détenteur prudent, l'interface devrait proposer d'exporter le contexte, de basculer sur une machine déconnectée, puis de rapporter la transaction signée. La séparation existe déjà en ligne de commande, il reste à la rendre visible ici.

Windows demande une note d'installation dédiée, Python n'étant pas présent par défaut.

## Un point de fond sur l'objectif

Rendre cet outil agréable à utiliser est utile, mais ce n'est pas la bonne mesure du succès.

La plupart de tes détenteurs ne devraient jamais s'en servir. Une interface réussie, ici, est une interface qui explique clairement le risque et qui laisse partir la majorité des visiteurs sans qu'ils aient rien touché. Le geste que tu veux rendre facile n'est pas la récupération, c'est la vérification, et elle ne demande aucune clé.

C'est pour cette raison que l'étape 01 se termine par « Ne rien faire » plutôt que par un appel à continuer, et que le bouton rouge porte le nom de ce qu'il détruit. Une interface de récupération qui donne envie de récupérer travaillerait contre le produit.
