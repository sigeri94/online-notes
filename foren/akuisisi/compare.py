import os
import hashlib
from datetime import datetime

def md5sum(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def scan_folder(base_path):
    files = {}
    for root, _, filenames in os.walk(base_path):
        for name in filenames:
            full_path = os.path.join(root, name)
            rel_path = os.path.relpath(full_path, base_path)

            files[rel_path] = {
                "md5": md5sum(full_path),
                "mtime": os.path.getmtime(full_path)
            }
    return files

def human_time(epoch):
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")

def compare_A_to_B(folder_A, folder_B):
    A = scan_folder(folder_A)
    B = scan_folder(folder_B)

    print("\n=== KOMPARASI A ➜ B ===")

    for file_path in sorted(A.keys()):
        if file_path not in B:
            print(f"[MISSING_IN_B] {file_path}")
            continue

        a = A[file_path]
        b = B[file_path]

        if a["md5"] != b["md5"]:
            print(f"[CONTENT_CHANGED] {file_path}")
            print(f"  MD5 A : {a['md5']}")
            print(f"  MD5 B : {b['md5']}")
            print(f"  Time A: {human_time(a['mtime'])}")
            print(f"  Time B: {human_time(b['mtime'])}")
            print("-" * 60)

        elif a["mtime"] != b["mtime"]:
            print(f"[TIME_CHANGED] {file_path}")
            print(f"  Time A: {human_time(a['mtime'])}")
            print(f"  Time B: {human_time(b['mtime'])}")
            print("-" * 60)

if __name__ == "__main__":
    folder_A = r"D:\baseline_source"
    folder_B = r"D:\target_source"

    compare_A_to_B(folder_A, folder_B)
