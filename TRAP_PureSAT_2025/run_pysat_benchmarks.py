#!/usr/bin/env python3
'''
Master Benchmark Test Runner for Glucose4 (PySAT) Pure Boolean Framework.
Runs NAND2, NOR3, and AOI22 benchmarks sequentially and logs execution stats.

Author:     Antigravity / Pure SAT Framework
Python:     3.10+
'''

import os
import sys
import datetime
import time
import subprocess

def main():
    base_dir = r'C:\Users\ADMIN\Downloads\TRANSAT-main\TRAP_PureSAT_2025'
    trap_2025_dir = r'C:\Users\ADMIN\Downloads\TRANSAT-main\TRAP_for_SAT_2025'
    logs_dir = os.path.join(base_dir, 'logs')
    os.makedirs(logs_dir, exist_ok=True)

    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    summary_fn = os.path.join(logs_dir, f'pysat_summary_{timestamp}.log')

    tests = [
        ("Test08-TRAP_NAND2", "NAND2 - 2 inputs", "test/Test08-TRAP_NAND2/trapNAND2.py", "test/Test08-TRAP_NAND2/trapNAND2_io.csv", "test/Test08-TRAP_NAND2/nand2PL.py"),
        ("Test09-TRAP_NOR3", "NOR3 - 3 inputs", "test/Test09-TRAP_NOR3/trapNOR3.py", "test/Test09-TRAP_NOR3/trapNOR3_io.csv", "test/Test09-TRAP_NOR3/nor3PL.py"),
        ("Test10-TRAP_AOI22", "AOI22 - 4 inputs", "test/Test10-TRAP_AOI22/trapAOI22.py", "test/Test10-TRAP_AOI22/trapAOI22_io.csv", "test/Test10-TRAP_AOI22/aoi22PL.py")
    ]

    summary_lines = []
    summary_lines.append("="*80)
    summary_lines.append(f"PURESAT (GLUCOSE4) MASTER BENCHMARK SUMMARY - {timestamp}")
    summary_lines.append("="*80 + "\n")

    print("\n" + "="*80)
    print(f"PURESAT (GLUCOSE4) BENCHMARK SUITE STARTING AT {timestamp}")
    print("="*80 + "\n")

    for idx, (t_folder, t_name, pl_file, io_csv, oracle_file) in enumerate(tests, 1):
        print(f"[{idx}/3] Executing Glucose4 PureSAT Attack on: {t_name}...")
        t_start = time.time()
        start_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Run pysatAttack
        cmd_attack = [
            sys.executable, "-m", "src.pysatAttack",
            pl_file, io_csv, oracle_file, t_folder, "-f"
        ]
        res_attack = subprocess.run(cmd_attack, cwd=base_dir, capture_output=True, text=True)

        # Run satVerify
        cmd_verify = [
            sys.executable, "-m", "src.satVerify_cli",
            "work/extracted_key.csv", oracle_file, io_csv
        ]
        res_verify = subprocess.run(cmd_verify, cwd=trap_2025_dir, capture_output=True, text=True)

        duration = time.time() - t_start
        attack_ok = "SUCCESSFUL" in res_attack.stdout or "GLUCOSE4 SAT ATTACK SUCCESSFUL" in res_attack.stdout
        verify_ok = "SAT VERIFICATION SUCCESSFUL" in res_verify.stdout

        status_attack = "SUCCESS" if attack_ok else "FAILED"
        status_verify = "SUCCESSFUL 100%" if verify_ok else "FAILED"

        entry = f"""Testcase #{idx}: {t_name}
  - Start Time:      {start_str}
  - Duration:        {duration:.2f} seconds
  - Glucose4 Attack: {status_attack}
  - Key Verify:      {status_verify}
--------------------------------------------------------------------------------"""
        print(entry)
        summary_lines.append(entry)

    summary_content = "\n".join(summary_lines)
    with open(summary_fn, 'w') as f:
        f.write(summary_content)

    print("\n" + "="*80)
    print(f"ALL 3 PURESAT BENCHMARKS CONCLUDED!")
    print(f"Master summary saved to: {summary_fn}")
    print("="*80 + "\n")

if __name__ == '__main__':
    main()
