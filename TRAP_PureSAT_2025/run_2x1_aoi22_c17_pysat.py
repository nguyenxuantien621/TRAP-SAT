#!/usr/bin/env python3
'''
PureSAT (Glucose4) Attack Runner for 2x1 Fabric AOI22 & C17
Automatically saves extracted keys into respective test folders and maintains full logs.

Author:     Antigravity / Pure SAT Framework
Python:     3.10+
'''

import os
import sys
import shutil
import datetime
import time
import subprocess

def main():
    base_dir = r'C:\Users\ADMIN\Downloads\TRANSAT-main\TRAP_PureSAT_2025'
    trap_2025_dir = r'C:\Users\ADMIN\Downloads\TRANSAT-main\TRAP_for_SAT_2025'
    logs_dir = os.path.join(base_dir, 'logs')
    os.makedirs(logs_dir, exist_ok=True)

    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    summary_fn = os.path.join(logs_dir, f'pysat_2x1_aoi22_c17_summary_{timestamp}.log')

    tests = [
        (
            "Test15-TRAP_2x1_AOI22",
            "2x1 Fabric AOI22 - 4 inputs (345 keys)",
            "test/Test15-TRAP_2x1_AOI22/trap2x1AOI22.py",
            "test/Test15-TRAP_2x1_AOI22/trap2x1AOI22_io.csv",
            "test/Test15-TRAP_2x1_AOI22/aoi22PL.py",
            "test/Test15-TRAP_2x1_AOI22"
        ),
        (
            "Test16-TRAP_2x1_C17",
            "2x1 Fabric C17 - 5 inputs (345 keys)",
            "test/Test16-TRAP_2x1_C17/trap2x1C17.py",
            "test/Test16-TRAP_2x1_C17/trap2x1C17_io.csv",
            "test/Test16-TRAP_2x1_C17/c17.py",
            "test/Test16-TRAP_2x1_C17"
        )
    ]

    summary_lines = []
    summary_lines.append("=" * 80)
    summary_lines.append(f"PURESAT (GLUCOSE4) 2x1 FABRIC (AOI22 & C17) BENCHMARK - {timestamp}")
    summary_lines.append("=" * 80 + "\n")

    print("\n" + "=" * 80)
    print(f"PURESAT (GLUCOSE4) 2x1 FABRIC (AOI22 & C17) BENCHMARK STARTING AT {timestamp}")
    print("=" * 80 + "\n")

    for idx, (t_folder, t_name, pl_file, io_csv, oracle_file, dest_folder) in enumerate(tests, 1):
        print(f"[{idx}/{len(tests)}] Executing Glucose4 PureSAT Attack on 2x1 Fabric: {t_name}...")
        t_start = time.time()
        start_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Run pysatAttack with unbuffered output
        cmd_attack = [
            sys.executable, "-u", "-m", "src.pysatAttack",
            pl_file, io_csv, oracle_file, t_folder, "-f"
        ]
        
        process = subprocess.Popen(
            cmd_attack,
            cwd=base_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        attack_stdout_lines = []
        for line in process.stdout:
            print(line, end='')
            sys.stdout.flush()
            attack_stdout_lines.append(line)
            
        process.wait()
        attack_stdout = "".join(attack_stdout_lines)

        # Copy extracted_key.csv directly to the test folder
        src_key = os.path.join(base_dir, "work", "extracted_key.csv")
        dest_key = os.path.join(base_dir, dest_folder, "extracted_key.csv")
        if os.path.exists(src_key):
            shutil.copy2(src_key, dest_key)
            print(f"[*] Extracted key successfully saved to: {dest_key}")
        else:
            print(f"[!] Warning: {src_key} not found.")

        # Run satVerify to confirm 100% equivalence
        cmd_verify = [
            sys.executable, "-m", "src.satVerify_cli",
            dest_key, oracle_file, io_csv
        ]
        res_verify = subprocess.run(cmd_verify, cwd=trap_2025_dir, capture_output=True, text=True)

        duration = time.time() - t_start
        attack_ok = "SUCCESSFUL" in attack_stdout or "Key extracted successfully" in attack_stdout or "concluded" in attack_stdout
        verify_ok = "SAT VERIFICATION SUCCESSFUL" in res_verify.stdout

        status_attack = "SUCCESS" if attack_ok else "FAILED"
        status_verify = "SUCCESSFUL 100%" if verify_ok else "FAILED"

        entry = f"""Testcase #{idx}: {t_name}
  - Start Time:      {start_str}
  - Duration:        {duration:.2f} seconds ({duration/60:.2f} mins)
  - Glucose4 Attack: {status_attack}
  - Key Verify:      {status_verify}
  - Key Saved To:    {dest_key}
--------------------------------------------------------------------------------"""
        print(entry)
        summary_lines.append(entry)

    summary_content = "\n".join(summary_lines)
    with open(summary_fn, 'w') as f:
        f.write(summary_content)

    print("\n" + "=" * 80)
    print("ALL 2x1 PURESAT (AOI22 & C17) BENCHMARKS CONCLUDED!")
    print(f"Master summary saved to: {summary_fn}")
    print("=" * 80 + "\n")

if __name__ == '__main__':
    main()
