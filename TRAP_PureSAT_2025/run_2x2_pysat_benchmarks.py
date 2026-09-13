#!/usr/bin/env python3
'''
Master 2x2 Fabric Benchmark Test Runner for Glucose4 (PySAT) Pure Boolean Framework.
Runs 2x2 Fabric NAND2, NOR3, and AOI22 benchmarks (708 key bits each) sequentially.

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
    summary_fn = os.path.join(logs_dir, f'pysat_2x2_summary_{timestamp}.log')

    tests = [
        ("Test11-TRAP_2x2_NAND2", "2x2 Fabric NAND2 - 2 inputs (708 keys)", "test/Test11-TRAP_2x2_NAND2/trap2x2NAND2.py", "test/Test11-TRAP_2x2_NAND2/trap2x2NAND2_io.csv", "test/Test11-TRAP_2x2_NAND2/nand2PL.py"),
        ("Test12-TRAP_2x2_NOR3", "2x2 Fabric NOR3 - 3 inputs (708 keys)", "test/Test12-TRAP_2x2_NOR3/trap2x2NOR3.py", "test/Test12-TRAP_2x2_NOR3/trap2x2NOR3_io.csv", "test/Test12-TRAP_2x2_NOR3/nor3PL.py"),
        ("Test13-TRAP_2x2_AOI22", "2x2 Fabric AOI22 - 4 inputs (708 keys)", "test/Test13-TRAP_2x2_AOI22/trap2x2AOI22.py", "test/Test13-TRAP_2x2_AOI22/trap2x2AOI22_io.csv", "test/Test13-TRAP_2x2_AOI22/aoi22PL.py")
    ]

    summary_lines = []
    summary_lines.append("="*80)
    summary_lines.append(f"PURESAT (GLUCOSE4) 2x2 FABRIC BENCHMARK SUMMARY - {timestamp}")
    summary_lines.append("="*80 + "\n")

    print("\n" + "="*80)
    print(f"PURESAT (GLUCOSE4) 2x2 FABRIC BENCHMARK SUITE STARTING AT {timestamp}")
    print("="*80 + "\n")

    for idx, (t_folder, t_name, pl_file, io_csv, oracle_file) in enumerate(tests, 1):
        print(f"[{idx}/3] Executing Glucose4 PureSAT Attack on 2x2 Fabric: {t_name}...")
        t_start = time.time()
        start_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Run pysatAttack
        cmd_attack = [
            sys.executable, "-u", "-m", "src.pysatAttack",
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
    print(f"ALL 2x2 PURESAT BENCHMARKS CONCLUDED!")
    print(f"Master 2x2 summary saved to: {summary_fn}")
    print("="*80 + "\n")

if __name__ == '__main__':
    main()
