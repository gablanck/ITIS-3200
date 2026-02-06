import os
import json
import hashlib
from datetime import datetime

HASH_TABLE_NAME = "hash_table.json"
HASH_ALGO = "sha256"
CHUNK_SIZE = 1024 * 1024 

"""Calculates the cryptographic hash of a file’s contents."""
def hash_file(filepath: str, algo: str = HASH_ALGO) -> str:
    h = hashlib.new(algo)
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

"""Navigates through the directory and returns a dict"""
def traverse_directory(directory: str) -> dict:
    file_hashes = {}
    directory = os.path.abspath(directory)

    for root, _, files in os.walk(directory):
        for name in files:
            path = os.path.join(root, name)

            if os.path.abspath(path) == os.path.abspath(os.path.join(directory, HASH_TABLE_NAME)):
                continue

            try:
                file_hashes[os.path.abspath(path)] = hash_file(path)
            except (PermissionError, FileNotFoundError) as e:
                print(f"[SKIP] {path} ({e})")

    return file_hashes

"""Generates a JSON file containing filepath and hash for each file."""
def generate_table(directory: str, output_path: str = None) -> str:

    directory = os.path.abspath(directory)
    hashes = traverse_directory(directory)

    table = {
        "meta": {
            "algorithm": HASH_ALGO,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "root_directory": directory,
        },
        "files": [{"filepath": fp, "hash": hv} for fp, hv in sorted(hashes.items())],
    }

    if output_path is None:
        output_path = os.path.join(directory, HASH_TABLE_NAME)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(table, f, indent=2)

    return f"Hash table generated: {output_path}"


def load_table(table_path: str) -> dict:
    with open(table_path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_table(table: dict, table_path: str) -> None:
    with open(table_path, "w", encoding="utf-8") as f:
        json.dump(table, f, indent=2)

"""
Reads from the generated hash table, traverses directory, recomputes hashes,
compares computed hashes to stored hashes. Prints valid/invalid for each file,
plus detects added/deleted files.
"""
def validate_hash(directory: str, table_path: str, enable_rename_fix: bool = True) -> None:
    
    directory = os.path.abspath(directory)
    table = load_table(table_path)

    algo = table.get("meta", {}).get("algorithm", HASH_ALGO)
    stored_list = table.get("files", [])

    stored_by_path = {item["filepath"]: item["hash"] for item in stored_list}
    stored_by_hash = {}
    for item in stored_list:
        stored_by_hash.setdefault(item["hash"], []).append(item["filepath"])

    current_by_path = traverse_directory(directory)

    print("\n--- Verification Results ---")

    deleted_paths = []
    for path, old_hash in stored_by_path.items():
        if path not in current_by_path:
            deleted_paths.append(path)
            continue

        new_hash = current_by_path[path]
        if new_hash == old_hash:
            print(f"[VALID]   {path}")
        else:
            print(f"[INVALID] {path} (hash changed)")

    new_paths = [p for p in current_by_path.keys() if p not in stored_by_path]
    for p in new_paths:
        print(f"[NEW]     {p}")

    for p in deleted_paths:
        print(f"[DELETED] {p}")

    updated = False
    if enable_rename_fix:

        deleted_hashes = [(p, stored_by_path[p]) for p in deleted_paths]
        for new_p in list(new_paths):
            new_h = current_by_path[new_p]

            match = next(((old_p, old_h) for (old_p, old_h) in deleted_hashes if old_h == new_h), None)
            if match:
                old_p, _ = match
                print(f"[RENAMED] {old_p}  ->  {new_p} (hash unchanged)")

                table["files"] = [x for x in table["files"] if x["filepath"] != old_p]
                table["files"].append({"filepath": new_p, "hash": new_h})
                updated = True

                deleted_hashes = [x for x in deleted_hashes if x[0] != old_p]
                new_paths.remove(new_p)

        if updated:
            table["meta"]["updated_at"] = datetime.now().isoformat(timespec="seconds")
            save_table(table, table_path)
            print(f"\n[UPDATE] Hash table updated for detected renames: {table_path}")

    print("\n--- Done ---\n")


def main():
    print("Hash Table Program")
    print("1) Generate a new hash table")
    print("2) Verify hashes using an existing hash table")
    choice = input("Select an option (1 or 2): ").strip()

    if choice == "1":
        directory = input("Enter directory path to hash: ").strip()
        if not os.path.isdir(directory):
            print("Error: That directory does not exist.")
            return
        msg = generate_table(directory)
        print(msg)

    elif choice == "2":
        directory = input("Enter directory path to verify: ").strip()
        if not os.path.isdir(directory):
            print("Error: That directory does not exist.")
            return

        table_path = input(f"Enter hash table path (.json) [default: {os.path.join(os.path.abspath(directory), HASH_TABLE_NAME)}]: ").strip()
        if not table_path:
            table_path = os.path.join(os.path.abspath(directory), HASH_TABLE_NAME)

        if not os.path.isfile(table_path):
            print("Error: Hash table JSON file not found.")
            return

        validate_hash(directory, table_path, enable_rename_fix=True)

    else:
        print("Invalid option. Please choose 1 or 2.")


if __name__ == "__main__":
    main()