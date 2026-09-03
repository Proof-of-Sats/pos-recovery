# À lire avant toute manipulation de votre carte

## L'essentiel en trois phrases

Votre carte contient un satoshi issu du plus ancien bitcoin encore en circulation. Ce satoshi peut être détruit de façon définitive par une seule opération mal faite, et cette opération est précisément celle que tout portefeuille Bitcoin vous proposera par défaut. Si vous ne faites rien, il ne risque rien.

## Ne balayez jamais la clé avec un portefeuille standard

Un portefeuille Bitcoin classique, quel qu'il soit, propose une fonction d'importation ou de balayage de clé privée. Sur une carte Proof of Sats, cette fonction détruit le satoshi rare dans environ la moitié des cas.

La raison est technique mais son effet est simple. Votre carte détient une sortie de 546 satoshis. Le satoshi historique en occupe un seul, et sa place dans cette sortie varie d'une carte à l'autre. Sur une partie de la série 1, il se trouve en dernière position. Or les frais de minage se prélèvent toujours sur la fin de la séquence. Un portefeuille qui prend ses frais sur cette unique sortie de 546 satoshis envoie donc le satoshi rare au mineur, avec le reste des frais. Il n'apparaît nulle part, il n'est pas récupérable, et personne ne peut le rendre.

Le portefeuille ne vous avertira pas. Il affichera une transaction réussie. Les bitcoins arriveront bien à destination. Seul le satoshi qui donne sa valeur à la carte aura disparu.

## Le satoshi n'a pas vocation à quitter la carte

C'est le point le plus important, et il n'est pas une précaution juridique.

Votre carte est un objet scellé. La clé privée est imprimée sous une étiquette VOID qui garde une trace irréversible de son ouverture, comme l'hologramme d'une pièce Casascius. Un exemplaire dont le scellé est intact et un exemplaire dont le scellé a été ouvert ne sont pas le même objet, et ne se revendent pas au même prix. L'ouverture est un acte à sens unique.

Le satoshi n'a pas besoin d'être déplacé pour être à vous. Il est déjà à une adresse dont vous seul détenez la clé, et il y reste sans action de votre part, sans frais, sans échéance et sans dépendance à un service tiers. La blockchain Bitcoin le conserve à votre place.

## Vous pouvez tout vérifier sans rien ouvrir

Chaque carte porte deux QR codes qui mènent à sa page de vérification sur verify.raresatscards.com. Cette page affiche l'adresse Bitcoin, la sortie non dépensée, le numéro exact du satoshi, sa position dans la sortie et le bloc d'origine. Ces informations proviennent de la blockchain, pas de nous. Vous pouvez les recouper sur n'importe quel explorateur public, ou sur votre propre nœud si vous en faites tourner un.

L'authenticité se vérifie donc entièrement de l'extérieur. Le scellé ne cache rien qui soit nécessaire à la preuve. Il ne contient que la clé de dépense.

## Si vous décidez malgré tout de récupérer le satoshi

Vous en avez le droit, c'est votre bien. Mais la manipulation demande un outil spécifique.

Utilisez exclusivement l'outil `pos-recover` fourni avec la carte et disponible sur raresatscards.com. Il construit la seule forme de transaction qui préserve le satoshi quelle que soit sa position, et il refuse de signer si les conditions ne sont pas réunies. Vous aurez besoin d'une seconde source de bitcoins, quelques milliers de satoshis, pour payer les frais sans toucher aux 546 satoshis de la carte.

Si vous êtes à l'aise techniquement, la procédure manuelle équivalente est documentée dans `PROCEDURE-TECHNIQUE.md`, avec les commandes `bitcoin-cli` correspondantes. Vous n'êtes pas obligé d'exécuter notre script.

Trois choses à ne pas faire, dans l'ordre de gravité :

Ne saisissez la clé privée dans aucun portefeuille mobile ou de bureau, même en lecture seule, même pour vérifier le solde. Certains balaient automatiquement à l'import.

Ne photographiez pas la clé privée et ne la saisissez pas dans un navigateur, un gestionnaire de notes, un outil en ligne ou un modèle de langage. Une clé qui a touché un écran connecté est une clé compromise.

Ne demandez à personne de faire l'opération pour vous, y compris à nous. Nous ne détenons aucune clé de la série 1, elles ont été détruites après impression. Quiconque vous propose de s'en occuper vous demande en réalité de lui donner votre satoshi.

## En cas de doute

Écrivez avant de manipuler, pas après. Une question coûte un e-mail. Une erreur coûte un satoshi qui existe en cent exemplaires dans le monde.

Contact : [adresse de support]
Vérification : verify.raresatscards.com
Outil : raresatscards.com/recover
