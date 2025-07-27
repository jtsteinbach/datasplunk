#!/usr/bin/env python3
# ──────────────────────────────
#   DataSplunk           v1.0.0
#   Author    jts.gg/datasplunk
#   License   r2.jts.gg/license
# ──────────────────────────────

import os
import re
import sys
import mmap
import concurrent.futures

# ────── constants ──────
VERSION = "v1.0.0"
MAGIC_SIGNATURES = {
    b'\x7fELF': 'ELF (Linux)',
    b'MZ': 'PE/COFF (Windows)',
    b'\xfe\xed\xfa\xce': 'Mach-O 32 LE',
    b'\xce\xfa\xed\xfe': 'Mach-O 32 BE',
    b'\xfe\xed\xfa\xcf': 'Mach-O 64 LE',
    b'\xcf\xfa\xed\xfe': 'Mach-O 64 BE',
    b'\xca\xfe\xba\xbe': 'Java .class'
}

# ────── check for binary ──────
def is_compiled_code(file_path):
    if not os.path.isfile(file_path):
        return False

    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(4)
            if len(chunk) < 2:
                return False

            if chunk.startswith(b'MZ'):
                return True

            if chunk in MAGIC_SIGNATURES:
                return True

    except Exception:
        pass

    return False

# ────── datamine strings from binary files ──────
def extract_strings_from_binary(file_path, min_str_len=4):
    results = []
    try:
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return results

        with open(file_path, 'rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                ascii_matches = re.findall(rb'[ -~]+', mm)
                for match in ascii_matches:
                    candidate = match.decode('ascii', errors='ignore').strip()
                    if len(candidate) >= min_str_len:
                        results.append(candidate)

                hex_matches = re.findall(rb'[0-9A-Fa-f]{2,}', mm)
                for hm in hex_matches:
                    try:
                        hex_str = hm.decode('ascii')
                        raw_bytes = bytes.fromhex(hex_str)
                        possible_text = raw_bytes.decode('ascii', errors='ignore').strip()
                        if len(possible_text) >= min_str_len:
                            results.append(possible_text)
                    except Exception:
                        pass
    except Exception:
        pass

    return results

def process_file(file_path):
    if not is_compiled_code(file_path):
        return (file_path, [])
    extracted_strings = extract_strings_from_binary(file_path)
    return (file_path, extracted_strings)

def get_all_files(directory):
    all_files = []
    for root, dirs, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            all_files.append(file_path)
    return all_files

# ────── script handling ──────
def main_menu():
    print(f"""
    DataSplunk            {VERSION}
    https://jts.gg/datasplunk
    """)
    directory = input("[Scan] Directory > ").strip()
    if not directory:
        print("No directory provided. Exiting.")
        sys.exit(1)
    if not os.path.isdir(directory):
        print("Not a valid directory. Exiting.")
        sys.exit(1)

    output_file = input("[Output] File Path > ").strip()
    if not output_file:
        print("No output file provided. Exiting.")
        sys.exit(1)

    try:
        threads = int(input("[CPU] Number of threads (ex 2,4,8) > ").strip())
    except ValueError:
        threads = 2  # default

    return directory, output_file, threads

def main():
    directory, output_file, threads = main_menu()
    print(f"\n[!] Scanning directory: {directory}")
    print(f"[!] Saving to: {output_file}")
    print(f"[CPU] Using {threads} threads...\n")

    file_paths = get_all_files(directory)
    total_files = len(file_paths)
    print(f"[Scan] Found {total_files} files in directory. Checking for compiled code...\n")

    results = []
    completed_count = 0

    def show_progress(completed, total):
        pct = (completed / total) * 100
        bar = f"\r[!] {completed}/{total} files... {pct:.2f}%"
        sys.stdout.write(bar)
        sys.stdout.flush()

    # process in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_file = {executor.submit(process_file, fp): fp for fp in file_paths}
        for future in concurrent.futures.as_completed(future_to_file):
            file_path = future_to_file[future]
            try:
                file_result = future.result()
                results.append(file_result)
            except Exception as e:
                print(f"\nError processing {file_path}: {e}")
            finally:
                completed_count += 1
                show_progress(completed_count, total_files)
    print()

    with open(output_file, 'w', encoding='utf-8') as out_f:
        for (fpath, strings) in results:
            if not strings:
                continue
            out_f.write(f"File: {fpath}\n")
            out_f.write("=" * (len(fpath) + 6) + "\n\n")
            out_f.write("\n\n".join(strings))
            out_f.write("\n\n\n")

    print("[Completed] Extracted strings from recognized executables/compiled code have been saved.")
    input("[Exit] Press ENTER to exit...")
    return


# ────── entry point ──────
if __name__ == "__main__":
    main()
