# AdvPack Benchmark Runner

Bộ điều phối dùng để đưa các package AdvPack qua các model phát hiện malware và so sánh kết quả giữa bản gốc với bản adversarial.

## 1. Thư mục dữ liệu hiện tại

Project:

```text
/home/tkayyy/Malware/BenchMark-Runner
```

Dataset bạn đã thêm nằm tại:

```text
datasets/datasetAdvPack/
```

Cấu trúc chính:

```text
datasetAdvPack/
├── original/
│   └── package_dataset/
│       ├── benign/
│       └── malicious/
├── levels/
│   ├── l1-syntax-encoding/
│   ├── l2-structure-lifecycle/
│   ├── l3-semantic-llm-deception/
│   └── l4-ultimate-combo/
└── strategies/
    ├── s1-identifier-renaming/
    ├── s2-data-obfuscation/
    ├── s3-control-flow-restructuring/
    └── ...
```

Dataset local hiện có:

- 1.500 archive gốc/control trong `original/`.
- 2.000 archive trong 4 level, mỗi level 500 archive.
- 5.000 archive trong các strategy.
- Tổng cộng 8.500 archive.
- Sau khi ghép với archive gốc, có 7.000 cặp original/adversarial hợp lệ.

## 2. Tạo manifest

Manifest là file CSV chỉ ra runner cần đọc package nào. Nó không sao chép nội dung archive.

Chạy từ thư mục project:

```bash
cd /home/tkayyy/Malware/BenchMark-Runner

python3 scripts/build_manifest.py \
  --dataset-root datasets/datasetAdvPack \
  --original-root datasets/datasetAdvPack/original/package_dataset \
  --output datasets/manifest_advpack_pairs.csv
```

Ý nghĩa các tham số:

- `--dataset-root`: thư mục chứa `levels/` và `strategies/`.
- `--original-root`: thư mục chứa `benign/` và `malicious/`.
- `--output`: nơi lưu manifest được tạo.

Script sẽ:

1. Quét archive trong `levels/` và `strategies/`.
2. Lấy tên package và version từ đường dẫn adversarial.
3. Tìm archive gốc tương ứng trong `original/package_dataset/`.
4. Bỏ qua archive không tìm thấy bản gốc.
5. Ghi các cặp hợp lệ vào manifest.

## 3. Kiểm tra manifest

Xem số dòng và vài dòng đầu:

```bash
wc -l datasets/manifest_advpack_pairs.csv
head -5 datasets/manifest_advpack_pairs.csv
```

Manifest phải có các cột:

```text
package_id,original_path,adversarial_path,level,strategy,seed
```

Kiểm tra mọi đường dẫn có tồn tại:

```bash
python3 - <<'PY'
import csv
from pathlib import Path

manifest = Path("datasets/manifest_advpack_pairs.csv")
with manifest.open(encoding="utf-8", newline="") as file:
    rows = list(csv.DictReader(file))

missing_original = [
    row["original_path"] for row in rows
    if not Path(row["original_path"]).is_file()
]
missing_adversarial = [
    row["adversarial_path"] for row in rows
    if not Path(row["adversarial_path"]).is_file()
]

print("Số cặp:", len(rows))
print("Thiếu original:", len(missing_original))
print("Thiếu adversarial:", len(missing_adversarial))

assert rows
assert not missing_original
assert not missing_adversarial
PY
```

Kết quả hiện tại dự kiến:

```text
Số cặp: 7000
Thiếu original: 0
Thiếu adversarial: 0
```

## 4. Các model được runner gọi

### RAG

```text
Project: /home/tkayyy/Malware/RAG
Python:  /home/tkayyy/Malware/RAG/venv/bin/python
```

Nếu cần cấu hình lại:

```bash
export ADVPACK_RAG_ROOT=/home/tkayyy/Malware/RAG
export ADVPACK_RAG_PYTHON=/home/tkayyy/Malware/RAG/venv/bin/python
```

### EMPHunter

```text
Project: /home/tkayyy/Malware/EMPHunter/PyPI/EMPHunter-PyPI
Model:  /home/tkayyy/Malware/EMPHunter/PyPI/EMPHunter-PyPI/DataShare/local_models/pypi_static_classifier.joblib
Python: /home/tkayyy/Malware/EMPHunter/.venv/bin/python
```

Nếu cần cấu hình lại:

```bash
export ADVPACK_EMPHUNTER_ROOT=/home/tkayyy/Malware/EMPHunter/PyPI/EMPHunter-PyPI
export ADVPACK_EMPHUNTER_PYTHON=/home/tkayyy/Malware/EMPHunter/.venv/bin/python
export ADVPACK_EMPHUNTER_MODEL=/duong/dan/toi/model.joblib
```

### Killing Two Birds

```text
Project:    /home/tkayyy/Malware/KillingTwoBirdswithOneStone
Checkpoint: /home/tkayyy/Malware/KillingTwoBirdswithOneStone/outputs/pypi/model-final
Python:     /home/tkayyy/Malware/KillingTwoBirdswithOneStone/.venv/bin/python
```

Adapter sẽ trích xuất behavior sequence từ archive rồi chạy inference.

```bash
export ADVPACK_KTB_ROOT=/home/tkayyy/Malware/KillingTwoBirdswithOneStone
export ADVPACK_KTB_PYTHON=/home/tkayyy/Malware/KillingTwoBirdswithOneStone/.venv/bin/python
export ADVPACK_KTB_MODEL=/home/tkayyy/Malware/KillingTwoBirdswithOneStone/outputs/pypi/model-final
```

### DySec

DySec có model `.pkl`, nhưng cần chạy đủ pipeline:

```text
cài package -> thu eBPF trace -> tạo feature -> nạp model -> dự đoán
```

Adapter DySec hiện chưa tự động xử lý archive trong manifest và sẽ ghi `not_configured`. Không dùng kết quả cũ trong `/home/tkayyy/Malware/DySec/results/` cho dataset local mới.

## 5. Chạy pilot trước

Pilot nhỏ có sẵn tại:

```text
datasets/manifest_pilot.csv
```

Chạy 3 model đã tích hợp:

```bash
python3 benchmark_runner.py \
  --manifest datasets/manifest_pilot.csv \
  --baselines rag emphunter killing_two_birds \
  --output results/pilot.csv \
  --workers 1
```

Kiểm tra kết quả:

```bash
cat results/pilot.csv
```

## 6. Chạy toàn bộ dataset

Nên chạy từng model riêng để dễ theo dõi và tránh các model nạp môi trường khác nhau.

### RAG

```bash
python3 benchmark_runner.py \
  --manifest datasets/manifest_advpack_pairs.csv \
  --baselines rag \
  --output results/full_rag.csv \
  --workers 2 \
  --skip-existing
```

### EMPHunter

```bash
python3 benchmark_runner.py \
  --manifest datasets/manifest_advpack_pairs.csv \
  --baselines emphunter \
  --output results/full_emphunter.csv \
  --workers 2 \
  --skip-existing
```

### Killing Two Birds

Model này chậm hơn vì mỗi archive cần sequence extraction và inference. Nên để `workers=1`:

```bash
python3 benchmark_runner.py \
  --manifest datasets/manifest_advpack_pairs.csv \
  --baselines killing_two_birds \
  --output results/full_killing_two_birds.csv \
  --workers 1 \
  --skip-existing
```

Nếu chương trình bị dừng, chạy lại đúng lệnh cũ. `--skip-existing` sẽ bỏ qua các job đã có `status=ok`.

## 7. Đọc kết quả

CSV có các cột quan trọng:

```text
score_original
score_adversarial
detected_original
detected_adversarial
latency_ms
status
error
```

Ví dụ:

```text
score_original,score_adversarial,detected_original,detected_adversarial
0.82,0.23,true,false
```

Diễn giải: model phát hiện package gốc nhưng bị đánh lừa bởi package adversarial.

Runner chỉ tạo kết quả thô. Precision, Recall, F1, ASR và Delta F1 cần tính ở bước phân tích sau.

## 8. Thêm model mới

Không cần viết lại `benchmark_runner.py`. Mỗi model mới chỉ cần một adapter chuyển giao diện riêng của model về định dạng chung của runner.

### Bước 1: Xác định cách model chạy

Ghi lại các thông tin:

- đường dẫn project;
- Python/virtualenv cần dùng;
- file model hoặc checkpoint;
- lệnh inference;
- định dạng output, ví dụ JSON, CSV hoặc stdout;
- threshold để quyết định `detected`.

Không thay đổi preprocessing, tokenizer, threshold hoặc checkpoint nếu muốn kết quả so sánh được với lần chạy trước.

### Bước 2: Viết adapter

Có thể thêm hàm vào `baselines/model_adapters.py` hoặc tạo file riêng trong `baselines/`. Adapter phải nhận một `PackageCase` và trả về `BaselineResult`:

```python
def run_new_model(case: PackageCase) -> BaselineResult:
    started = time.perf_counter()

    original_score = score_one(case.original_path)
    adversarial_score = score_one(case.adversarial_path)

    return BaselineResult(
        "new_model",
        original_score,
        adversarial_score,
        original_score >= 0.5,
        adversarial_score >= 0.5,
        (time.perf_counter() - started) * 1000,
    )
```

Nếu model trả nhãn trực tiếp thay vì score, adapter có thể dùng score `1.0` cho malicious và `0.0` cho benign, nhưng nên giữ score thật nếu model có cung cấp.

### Bước 3: Đăng ký model với runner

Mở `benchmark_runner.py` và thêm adapter vào `BASELINES`:

```python
from baselines.model_adapters import run_new_model

BASELINES = {
    "rag": run_rag,
    "emphunter": run_emphunter,
    "killing_two_birds": run_killing_two_birds,
    "dysec": run_dysec,
    "new_model": run_new_model,
}
```

Tên `new_model` sẽ trở thành giá trị dùng cho `--baselines` và cột `baseline` trong CSV.

### Bước 4: Chạy thử trên pilot

Kiểm tra syntax:

```bash
python3 -m compileall -q benchmark_runner.py baselines
```

Chạy model mới trên 3 package pilot:

```bash
python3 benchmark_runner.py \
  --manifest datasets/manifest_pilot.csv \
  --baselines new_model \
  --output results/pilot_new_model.csv \
  --workers 1
```

Kiểm tra CSV:

```bash
cat results/pilot_new_model.csv
```

Chỉ chuyển sang full dataset khi các dòng có `status=ok`, score nằm trong khoảng hợp lệ và đường dẫn original/adversarial được xử lý đúng.

### Bước 5: Chạy full dataset

```bash
python3 benchmark_runner.py \
  --manifest datasets/manifest_advpack_pairs.csv \
  --baselines new_model \
  --output results/full_new_model.csv \
  --workers 1 \
  --skip-existing
```

Số `workers` tùy thuộc model. Model static thường có thể dùng 2--4 workers; model cần GPU, Docker, `sudo` hoặc tài nguyên kernel nên bắt đầu với `workers=1`.

## 9. Cảnh báo an toàn

Chỉ chạy package malware trong máy ảo biệt lập, không chứa SSH key, token hoặc dữ liệu quan trọng. Không chạy DySec song song nhiều package vì eBPF và `sudo` dùng chung tài nguyên kernel.
