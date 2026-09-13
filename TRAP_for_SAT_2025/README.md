# TRAP for SAT (2025 Q1 Research Project)

> **Paper Title**: *A TRAP for SAT: On the Imperviousness of a Transistor-Level Programmable Fabric to Satisfiability-Based Attacks* (IEEE 2025 Q1)  
> **Author**: Aric Fowler et al.

---

## 📌 Giới thiệu dự án

Dự án này là phiên bản độc lập (**standalone**) được trích xuất nhằm tập trung **100% vào công trình bài báo năm 2025 ("A TRAP for SAT")**. Tất cả các phần mở rộng không thuộc phạm vi bài báo 2025 (như State Location detection 2024, Charge-Trap device builders, ABC attack wrapper, v.v.) đã được tinh giản.

TRAP (Transistor-Level Programmable Fabric) giới thiệu kiến trúc bảo mật phần cứng ở cấp độ **transistor** (nâng cấp so với gate-level logic locking truyền thống), giúp chống lại các cuộc tấn công giải mã chìa khóa dựa trên SAT (Satisfiability-based SAT Attacks).

---

## 📁 Cấu trúc thư mục

```text
TRAP_for_SAT_2025/
├── paper/
│   └── 2025 (Q1) - A TRAP for SAT - On the Imperviousness of aTransistor-Level Programmable Fabric to Satisfiability-Based Attacks.pdf
├── src/
│   ├── __init__.py
│   ├── globals.py                # Định nghĩa các hằng số và danh sách cổng logic
│   ├── trapFabricBuilder.py      # Tạo mô hình Z3 Propositional Logic cho TRAP fabric
│   ├── trapFabricBuilder_cli.py  # CLI Wrapper cho trapFabricBuilder
│   ├── satAttack.py              # Thuật toán SAT Attack ở cấp độ Transistor (TRANSAT)
│   ├── satAttack_cli.py          # CLI Wrapper cho satAttack (hỗ trợ Windows & Linux)
│   ├── satVerify.py              # Kiểm chứng chìa khóa tìm được bằng Oracle
│   └── satVerify_cli.py          # CLI Wrapper cho satVerify
├── test/
│   └── Test08-TRAP_NAND2/        # Benchmark mẫu: TRAP NAND2 1x1 Unit
│       ├── ioMap.csv
│       ├── nand2PL.py
│       ├── trapNAND2.py
│       ├── trapNAND2_io.csv
│       └── twoInputGates.v
├── pyproject.toml
├── setup.py
└── README.md
```

---

## 🚀 Hướng dẫn cài đặt và sử dụng

### 1. Cài đặt phụ thuộc
Yêu cầu Python >= 3.8 và gói `z3-solver`:

```bash
pip install z3-solver
```

Hoặc cài đặt package ở chế độ editable:

```bash
pip install -e .
```

---

### 2. Các công cụ CLI chính

#### A. `trapFabricBuilder` (Xây dựng Mô hình TRAP Fabric)
Tạo ra file logic Z3 đại diện cho mạng lưới transistor TRAP theo kích thước ma trận `[hàng x cột]` và sơ đồ chân I/O.

```bash
python -m src.trapFabricBuilder_cli <numRows> <numCols> <pinMap.csv> -o <outputName>
```

*Ví dụ:*
```bash
python -m src.trapFabricBuilder_cli 1 1 test/Test08-TRAP_NAND2/ioMap.csv -o test/Test08-TRAP_NAND2/trapNAND2
```

---

#### B. `satAttack` (Thực hiện Tấn công SAT Attack)
Tiến hành thuật toán SAT Attack cấp độ transistor để tìm chìa khóa giải mã (Key) từ mô hình TRAP.

```bash
python -m src.satAttack_cli <targetPL.py> <targetIO.csv> -o work/extracted_key.csv
```

*Ví dụ:*
```bash
python -m src.satAttack_cli test/Test08-TRAP_NAND2/trapNAND2.py test/Test08-TRAP_NAND2/trapNAND2_io.csv
```

> **Ghi chú tính năng tương thích Windows:**  
> Công cụ tự động hỗ trợ môi trường Windows PowerShell/CMD và tự động kích hoạt **Z3 Python Oracle Fallback** nếu máy tính chưa cài đặt Verilog Simulator (`iverilog`).

---

#### C. `satVerify` (Kiểm chứng Chìa Khóa)
So sánh chìa khóa đã giải mã (`extracted_key.csv`) với mạch thật (Golden Oracle) để xác nhận độ chính xác 100%.

```bash
python -m src.satVerify_cli <extractedKey.csv> <goldenOraclePL.py> <targetIO.csv>
```

*Ví dụ:*
```bash
python -m src.satVerify_cli work/extracted_key.csv test/Test08-TRAP_NAND2/nand2PL.py test/Test08-TRAP_NAND2/trapNAND2_io.csv
```

---

## 📊 Kết quả mẫu khi chạy thử nghiệm (Benchmark Test08)

1. **Chạy Tấn công SAT:**
```bash
python -m src.satAttack_cli test/Test08-TRAP_NAND2/trapNAND2.py test/Test08-TRAP_NAND2/trapNAND2_io.csv
```
Output:
```text
Iteration 1... DIP found: {'a': False, 'b': False}
Key extracted! Written to work/extracted_key.csv
```

2. **Chạy Kiểm chứng:**
```bash
python -m src.satVerify_cli work/extracted_key.csv test/Test08-TRAP_NAND2/nand2PL.py test/Test08-TRAP_NAND2/trapNAND2_io.csv
```
Output:
```text
SAT VERIFICATION SUCCESSFUL!
The extracted key correctly configured the TRAP fabric to perform the target function.
```

---

## 📖 Trích dẫn bài báo (Citation)

```bibtex
@article{fowler2025trap,
  title={A TRAP for SAT: On the Imperviousness of a Transistor-Level Programmable Fabric to Satisfiability-Based Attacks},
  author={Fowler, Aric and et al.},
  journal={IEEE Transactions / Conference (Q1)},
  year={2025}
}
```
