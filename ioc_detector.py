import os
import re
import xml.etree.ElementTree as ET
import hashlib
from collections import defaultdict

# --- Configuration (modifie ici si tu veux scanner un autre dossier) ---
ioc_folder = r'C:\Users\mahmo\OneDrive\Desktop\TP3 PART 2\IOC_MD5_Hash_Detection_Script'
# Par défaut on scanne le même dossier ; change si nécessaire
directory_to_scan = ioc_folder
# ---------------------------------------------------------------------

MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')

def calculate_md5(file_path):
    """Calcule le MD5 d'un fichier et renvoie en MAJUSCULE."""
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest().upper()
    except Exception as e:
        print(f"Erreur lecture fichier {file_path}: {e}")
        return None

def extract_md5s_from_ioc(ioc_path):
    """Extrait les MD5 d'un fichier IOC (plusieurs méthodes: attribut type ou regex dans le texte)."""
    md5s = set()
    try:
        tree = ET.parse(ioc_path)
        root = tree.getroot()
        # Parcourir tous les éléments et chercher ceux qui ressemblent à 'Content' ou contiennent md5
        for elem in root.iter():
            tag_local = elem.tag.split('}')[-1]  # gère les namespaces: {uri}Content -> Content
            # 1) Si élément Content avec attribut type contenant 'md5'
            if tag_local.lower() == 'content':
                t = (elem.attrib.get('type') or '').lower()
                text = (elem.text or '').strip()
                if 'md5' in t and text:
                    candidate = re.sub(r'[^a-fA-F0-9]', '', text).upper()
                    if len(candidate) == 32:
                        md5s.add(candidate)
                else:
                    # 2) fallback: chercher des chaînes hex de 32 chars dans le texte
                    for m in MD5_RE.findall(text):
                        md5s.add(m.upper())
            else:
                # aussi vérifier n'importe quel texte pour des MD5
                text = (elem.text or '').strip()
                for m in MD5_RE.findall(text):
                    md5s.add(m.upper())
    except ET.ParseError as e:
        print(f"Parse error pour {ioc_path}: {e}")
    except Exception as e:
        print(f"Erreur extraction depuis {ioc_path}: {e}")
    return md5s

def load_all_ioc_hashes(folder):
    """Parcourt le dossier pour tous les .ioc et retourne dict md5 -> list(ioc_files)"""
    md5_to_iocs = defaultdict(list)
    if not os.path.isdir(folder):
        print(f"Le dossier IOC spécifié n'existe pas: {folder}")
        return md5_to_iocs

    for entry in os.listdir(folder):
        if entry.lower().endswith('.ioc'):
            path = os.path.join(folder, entry)
            hashes = extract_md5s_from_ioc(path)
            if hashes:
                for h in hashes:
                    md5_to_iocs[h].append(path)
            else:
                print(f"Aucun MD5 trouvé dans {path}")
    return md5_to_iocs

def scan_and_match(directory, md5_to_iocs):
    """Scanne le répertoire et affiche les fichiers correspondant aux MD5."""
    if not md5_to_iocs:
        print("Aucun MD5 chargé depuis les IOC. Rien à comparer.")
        return

    matches = []
    total_files = 0
    for dirpath, dirs, files in os.walk(directory):
        for filename in files:
            total_files += 1
            file_path = os.path.join(dirpath, filename)
            file_md5 = calculate_md5(file_path)
            if file_md5 is None:
                continue
            if file_md5 in md5_to_iocs:
                matches.append((file_path, file_md5, md5_to_iocs[file_md5]))

    print(f"\nFichiers scannés: {total_files}")
    if matches:
        print(f"==> {len(matches)} correspondance(s) trouvée(s) :")
        for file_path, md5, ioc_list in matches:
            print(f"- {file_path}\n  MD5: {md5}\n  Provenance IOC: ")
            for i in ioc_list:
                print(f"    • {i}")
    else:
        print("Aucune correspondance trouvée.")

if __name__ == "__main__":
    print("Chargement des fichiers .ioc dans :", ioc_folder)
    md5_to_iocs = load_all_ioc_hashes(ioc_folder)
    print(f"Total MD5 uniques extraits : {len(md5_to_iocs)}")
    # Optionnel: lister les MD5 extraits
    if md5_to_iocs:
        print("Exemple de MD5 extraits (jusqu'à 10) :")
        for idx, h in enumerate(list(md5_to_iocs.keys())[:10], 1):
            print(f"{idx}. {h}  (depuis {len(md5_to_iocs[h])} IOC file(s))")

    print("\nDébut du scan du dossier :", directory_to_scan)
    scan_and_match(directory_to_scan, md5_to_iocs)
    print("\nTerminé.")
