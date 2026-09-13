#!/usr/bin/env python3
'''
Benchmark Runner for 2x2 Fabric NAND2 and NOR3 (708 key bits) using Z3 SMT Baseline.

Author:     Antigravity / TRAP Z3 Framework
Python:     3.10+
'''

import os
import sys
import datetime
import time
import subprocess

def main():
    base_dir = r'C:\Users\ADMIN\Downloads\TRANSAT-main\TRAP_for_SAT_2025'
    logs_dir = os.path.join(base_dir, 'logs')
    os.makedirs(logs_dir, exist_ok=True)

    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    summary_fn = os.path.join(logs_dir, f'z3_2x2_nand2_nor3_summary_{timestamp}.log')

    tests = [
        ("Test11-TRAP_2x2_NAND2", "2x2 Fabric NAND2 - 2 inputs (708 keys)", "test/Test11-TRAP_2x2_NAND2/trap2x2NAND2.py", "test/Test11-TRAP_2x2_NAND2/trap2x2NAND2_io.csv", "test/Test11-TRAP_2x2_NAND2/nand2PL.py"),
        ("Test12-TRAP_2x2_NOR3", "2x2 Fabric NOR3 - 3 inputs (708 keys)", "test/Test12-TRAP_2x2_NOR3/trap2x2NOR3.py", "test/Test12-TRAP_2x2_NOR3/trap2x2NOR3_io.csv", "test/Test12-TRAP_2x2_NOR3/nor3PL.py")
    ]

    summary_lines = []
    summary_lines.append("="*80)
    summary_lines.append(f"Z3 SMT 2x2 FABRIC (NAND2 & NOR3) BENCHMARK SUMMARY - {timestamp}")
    summary_lines.append("="*80 + "\n")

    print("\n" + "="*80)
    print(f"Z3 SMT 2x2 FABRIC (NAND2 & NOR3) BENCHMARK SUITE STARTING AT {timestamp}")
    print("="*80 + "\n")

    for idx, (t_folder, t_name, pl_file, io_csv, oracle_file) in enumerate(tests, 1):
        print(f"[{idx}/2] Executing Z3 SMT Attack on 2x2 Fabric: {t_name}...")
        t_start = time.time()
        start_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Run satAttack_cli
        cmd_attack = [
            sys.executable, "-u", "-m", "src.satAttack_cli",
            pl_file, io_csv, oracle_file, t_folder, "-f"
        ]
        res_attack = subprocess.run(cmd_attack, cwd=base_dir, capture_output=True, text=True)

        # Run satVerify_cli
        cmd_verify = [
            sys.executable, "-m", "src.satVerify_cli",
            "work/extracted_key.csv", oracle_file, io_csv
        ]
        res_verify = subprocess.run(cmd_verify, cwd=base_dir, capture_output=True, text=True)

        duration = time.time() - t_start
        attack_ok = "Key extracted successfully" in res_attack.stdout or "concluded" in res_attack.stdout
        verify_ok = "SAT VERIFICATION SUCCESSFUL" in res_verify.stdout

        status_attack = "SUCCESS" if attack_ok else "FAILED"
        status_verify = "SUCCESSFUL 100%" if verify_ok else "FAILED"

        entry = f"""Testcase #{idx}: {t_name}
  - Start Time:      {start_str}
  - Duration:        {duration:.2f} seconds
  - Z3 SMT Attack:   {status_attack}
  - Key Verify:      {status_verify}
--------------------------------------------------------------------------------"""
        print(entry)
        print(res_attack.stdout)
        summary_lines.append(entry)

    summary_content = "\n".join(summary_lines)
    with open(summary_fn, 'w') as f:
        f.write(summary_content)

    print("\n" + "="*80)
    print(f"ALL 2x2 Z3 SMT (NAND2 & NOR3) BENCHMARKS CONCLUDED!")
    print(f"Master summary saved to: {summary_fn}")
    print("="*80 + "\n")

if __name__ == '__main__':
    main()
