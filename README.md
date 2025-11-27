# IOC MD5 Hash Detection Script

[![Python Version](https://img.shields.io/badge/Python-3.x-blue)](https://www.python.org/)

## Description

Ce script Python permet de scanner un dossier à la recherche de fichiers correspondant à des **hashes MD5 présents dans des fichiers IOC**. Il est principalement utilisé pour détecter des fichiers suspects ou compromises sur un système en comparant les hash avec ceux d'indicateurs de compromission (IOC).

Le script supporte :

* Lecture automatique de tous les fichiers `.ioc` dans un dossier donné.
* Extraction des MD5 depuis les fichiers IOC (via l'attribut `type="md5"` ou par regex dans le contenu).
* Scanning récursif d'un dossier pour calculer le MD5 de chaque fichier.
* Affichage des correspondances trouvées avec leur provenance (fichier IOC).

## Prérequis

* Python 3.x
* Aucun package externe requis, seulement les modules standard (`os`, `re`, `xml.etree.ElementTree`, `hashlib`, `collections`).

## Installation

1. Cloner le dépôt GitHub :

```bash
git clone https://github.com/<votre-utilisateur>/ioc-md5-scanner.git
```

2. Placer vos fichiers `.ioc` dans un dossier (par défaut le script lit tous les `.ioc` du dossier configuré).

## Utilisation

1. Ouvrir le script `ioc_md5_scanner.py`.
2. Modifier la configuration si nécessaire :

```python
ioc_folder = r'C:\chemin\vers\vos\fichiers_ioc'
directory_to_scan = r'C:\chemin\vers\dossier_a_scanner'
```

3. Exécuter le script :

```bash
python ioc_md5_scanner.py
```

## Fonctionnement

* `calculate_md5(file_path)` : calcule le MD5 d'un fichier.
* `extract_md5s_from_ioc(ioc_path)` : extrait les MD5 d'un fichier IOC.
* `load_all_ioc_hashes(folder)` : parcourt un dossier pour tous les `.ioc` et crée un dictionnaire `md5 -> [ioc_files]`.
* `scan_and_match(directory, md5_to_iocs)` : scanne le dossier et affiche les fichiers correspondant aux MD5 extraits.

## Exemple de sortie

```
Chargement des fichiers .ioc dans : C:\Users\mahmo\Desktop\IOC_MD5_Hash_Detection_Script
Total MD5 uniques extraits : 5
Exemple de MD5 extraits (jusqu'à 10) :
1. 1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6  (depuis 1 IOC file)
Début du scan du dossier : C:\Users\mahmo\Desktop\IOC_MD5_Hash_Detection_Script
Fichiers scannés: 20
==> 1 correspondance(s) trouvée(s) :
- C:\Users\mahmo\Desktop\IOC_MD5_Hash_Detection_Script\suspicious_sample.exe
  MD5: 1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6
  Provenance IOC:
    • C:\Users\mahmo\Desktop\IOC_MD5_Hash_Detection_Script\fichier_suspect.ioc
Terminé.
```

## Notes

* Les hash sont comparés en **MAJUSCULE** pour assurer la cohérence.
* Le script peut gérer plusieurs MD5 par fichier IOC.
* Si un fichier n’a pas pu être lu, une erreur sera affichée mais le script continue.

## Licence

Ce projet est sous licence MIT.
