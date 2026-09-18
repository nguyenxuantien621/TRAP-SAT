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
    summary_fn = os.path.join(logs_dir, f'pysat_2x2_c17_summary_{timestamp}.log')

    tests = [
        ("Test14-TRAP_2x2_C17", "2x2 Fabric C17 - 5 inputs (708 keys)", "test/Test14-TRAP_2x2_C17/trap2x2C17.py", "test/Test14-TRAP_2x2_C17/trap2x2C17_io.csv", "test/Test14-TRAP_2x2_C17/c17.py")
    ]

    summary_lines = []
    summary_lines.append("="*80)
    summary_lines.append(f"PURESAT (GLUCOSE4) 2x2 FABRIC C17 BENCHMARK SUMMARY - {timestamp}")
    summary_lines.append("="*80 + "\n")

    print("\n" + "="*80)
    print(f"PURESAT (GLUCOSE4) 2x2 FABRIC C17 BENCHMARK STARTING AT {timestamp}")
    print("="*80 + "\n")

    for idx, (t_folder, t_name, pl_file, io_csv, oracle_file) in enumerate(tests, 1):
        print(f"[{idx}/1] Executing Glucose4 PureSAT Attack on 2x2 Fabric: {t_name}...")
        t_start = time.time()
        start_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Run pysatAttack with unbuffered real-time output
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

        # Run satVerify
        key_file_abs = os.path.join(base_dir, "work", "extracted_key.csv")
        cmd_verify = [
            sys.executable, "-m", "src.satVerify_cli",
            key_file_abs, oracle_file, io_csv
        ]
        res_verify = subprocess.run(cmd_verify, cwd=trap_2025_dir, capture_output=True, text=True)

        duration = time.time() - t_start
        attack_ok = "SUCCESSFUL" in attack_stdout or "GLUCOSE4 SAT ATTACK SUCCESSFUL" in attack_stdout or "Key extracted successfully" in attack_stdout
        verify_ok = "SAT VERIFICATION SUCCESSFUL" in res_verify.stdout

        status_attack = "SUCCESS" if attack_ok else "FAILED"
        status_verify = "SUCCESSFUL 100%" if verify_ok else "FAILED"

        entry = f"""Testcase #{idx}: {t_name}
  - Start Time:      {start_str}
  - Duration:        {duration:.2f} seconds ({duration/60:.2f} mins)
  - Glucose4 Attack: {status_attack}
  - Key Verify:      {status_verify}
--------------------------------------------------------------------------------"""
        print(entry)
        summary_lines.append(entry)

    summary_content = "\n".join(summary_lines)
    with open(summary_fn, 'w') as f:
        f.write(summary_content)

    print("\n" + "="*80)
    print(f"2x2 PURESAT C17 BENCHMARK CONCLUDED!")
    print(f"Master summary saved to: {summary_fn}")
    print("="*80 + "\n")

if __name__ == '__main__':
    main()
