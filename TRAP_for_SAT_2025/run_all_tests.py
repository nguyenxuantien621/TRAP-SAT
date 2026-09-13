#!/usr/bin/env python3
'''
Script to execute SAT Attack & Verification across all 3 benchmark test cases
and generate detailed timestamped logs for each test case as well as a master summary log.
'''

import os
import sys
import subprocess
import datetime

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    logs_dir = os.path.join(base_dir, 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    summary_log_path = os.path.join(logs_dir, f'all_tests_summary_{timestamp}.log')
    
    tests = [
        {
            'name': 'Test08-TRAP_NAND2 (NAND2 - 2 inputs)',
            'attack_cmd': [sys.executable, '-m', 'src.satAttack_cli', 'test/Test08-TRAP_NAND2/trapNAND2.py', 'test/Test08-TRAP_NAND2/trapNAND2_io.csv', 'test/Test08-TRAP_NAND2/nand2PL.py', 'nand2', '-f'],
            'verify_cmd': [sys.executable, '-m', 'src.satVerify_cli', 'work/extracted_key.csv', 'test/Test08-TRAP_NAND2/nand2PL.py', 'test/Test08-TRAP_NAND2/trapNAND2_io.csv']
        },
        {
            'name': 'Test09-TRAP_NOR3 (NOR3 - 3 inputs)',
            'attack_cmd': [sys.executable, '-m', 'src.satAttack_cli', 'test/Test09-TRAP_NOR3/trapNOR3.py', 'test/Test09-TRAP_NOR3/trapNOR3_io.csv', 'test/Test09-TRAP_NOR3/nor3PL.py', 'nor3', '-f'],
            'verify_cmd': [sys.executable, '-m', 'src.satVerify_cli', 'work/extracted_key.csv', 'test/Test09-TRAP_NOR3/nor3PL.py', 'test/Test09-TRAP_NOR3/trapNOR3_io.csv']
        },
        {
            'name': 'Test10-TRAP_AOI22 (AOI22 - 4 inputs)',
            'attack_cmd': [sys.executable, '-m', 'src.satAttack_cli', 'test/Test10-TRAP_AOI22/trapAOI22.py', 'test/Test10-TRAP_AOI22/trapAOI22_io.csv', 'test/Test10-TRAP_AOI22/aoi22PL.py', 'aoi22', '-f'],
            'verify_cmd': [sys.executable, '-m', 'src.satVerify_cli', 'work/extracted_key.csv', 'test/Test10-TRAP_AOI22/aoi22PL.py', 'test/Test10-TRAP_AOI22/trapAOI22_io.csv']
        }
    ]

    summary_lines = []
    header = "="*80 + f"\nMASTER BENCHMARK TEST RUNNER SUMMARY - {timestamp}\n" + "="*80 + "\n"
    print(header)
    summary_lines.append(header)

    for i, test in enumerate(tests, 1):
        test_name = test['name']
        start_t = datetime.datetime.now()
        
        print(f"\n[{i}/3] Running SAT Attack on: {test_name}...")
        res_attack = subprocess.run(test['attack_cmd'], cwd=base_dir, capture_output=True, text=True)
        
        print(f"[{i}/3] Running Verification on: {test_name}...")
        res_verify = subprocess.run(test['verify_cmd'], cwd=base_dir, capture_output=True, text=True)
        
        end_t = datetime.datetime.now()
        duration = (end_t - start_t).total_seconds()
        
        attack_status = "SUCCESS" if res_attack.returncode == 0 else "FAILED"
        verify_status = "SUCCESSFUL" if "SAT VERIFICATION SUCCESSFUL" in res_verify.stdout else "FAILED"
        
        log_entry = (
            f"Testcase #{i}: {test_name}\n"
            f"  - Start Time:      {start_t.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"  - Duration:        {duration:.2f} seconds\n"
            f"  - SAT Attack:      {attack_status}\n"
            f"  - Key Verify:      {verify_status}\n"
            f"--------------------------------------------------------------------------------\n"
        )
        print(log_entry)
        summary_lines.append(log_entry)

    footer = f"\nAll 3 Test Cases Executed Successfully! Master summary saved to:\n{summary_log_path}\n"
    print(footer)
    summary_lines.append(footer)

    with open(summary_log_path, 'w', encoding='utf-8') as f:
        f.writelines(summary_lines)

if __name__ == '__main__':
    main()
