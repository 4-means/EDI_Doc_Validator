# EDI Comparison Tool (X12 & EDIFACT)

`x12_validator.py` compares a **pattern** (golden) EDI document with a **test** document (ANSI X12 or UN/EDIFACT) and exports a richly-formatted Excel workbook that highlights every difference it finds.

The generated workbook contains:
- **Summary** — interchange + functional group metadata, with match indicators
- **Segment Counts** — frequency delta for each segment tag
- **Segment Diff** — segment-level operations (insert/delete/replace)
- **Element Diff** — detailed element comparisons with ignore flags
- **Missing Segments** / **Extra Segments** — unmatched segments from each file
- **Pattern Elements** / **Test Elements** — flattened element values for quick filtering

The validator understands X12 856 (ship notice), 861 (receipt advice), and 863 (report of test results) transaction sets, aligning ST blocks by control number and matching HL/LIN/RCD loops intelligently. EDIFACT DESADV (ASN) and QALITY (quality report) messages are parsed automatically, with UNH/UNT blocks aligned by message reference. Volatile elements can be skipped through a configurable ignore-rules CSV.

## Requirements
- Python 3.9+
- Install dependencies:
  ```bash
  pip install -r requirements.txt
  ```

## Usage
```bash
python x12_validator.py \
  --pattern O856_X12_Pattern.txt \
  --test    O856_X12_Test.txt \
  --out     O856_X12_Comparison.xlsx
```

### Key Flags
- `--pattern` / `--test` — input EDI files (required)
- `--out` — destination Excel workbook (required)
- `--seg-term` — override the segment terminator (auto-detected otherwise)
- `--elem-sep` — override the element separator (X12 only; auto-detected otherwise)
- `--ignore-file` — CSV of ignore rules (see `O856_X12_config.csv` for format)
- `--tx` — force transaction/message type (e.g., `856`, `863`, `DESADV`, `QALITY`, or aliases such as `ASN`, `QUALITY`)

The tool validates that both files use the same EDI format and transaction/message type. Provide `--tx` only when you intentionally need to override auto-detection.

## Examples
Generate an 863 comparison with custom delimiters:
```bash
python x12_validator.py \
  --pattern O863_X12_Pattern.txt \
  --test    O863_X12_Test.txt \
  --out     O863_X12_Comparison.xlsx \
  --seg-term '~' \
  --elem-sep '*'
```

Compare an 861 receipt advice:
```bash
python x12_validator.py \
  --pattern 861/O861_AK_attern.txt \
  --test    861/O861_MittalBH_Pattern.txt \
  --out     861_compare.xlsx \
  --tx      861
```

Run an 856 comparison while ignoring specific qualifier combinations:
```bash
python x12_validator.py \
  --pattern O856_X12_Pattern.txt \
  --test    O856_X12_Test.txt \
  --out     O856_X12_Comparison.xlsx \
  --ignore-file O856_X12_config.csv
```

Compare an EDIFACT ASN (DESADV):
```bash
python x12_validator.py \
  --pattern O856_Edifact_Pattern.txt \
  --test    O856_Edifact_Test.txt \
  --out     O856_Edifact_Comparison.xlsx
```

## macOS tip (recommended)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python x12_validator.py --pattern file1 --test file2 --out report.xlsx
```

## Windows PowerShell tip
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python x12_validator.py --pattern file1 --test file2 --out report.xlsx
```

## Troubleshooting
- If Excel columns appear condensed, enable wrap text and widen columns; autosizing is applied but Excel may cap widths.
- Ensure the pattern and test files use the same delimiters or supply `--seg-term` / `--elem-sep`.
- Ignored segments/elements still appear in the sheets with `ignored=True` so you can verify the rule was applied.
