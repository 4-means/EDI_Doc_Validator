# EDI X12 Comparison Tool (Python)

This tool compares two EDI X12 files and generates an Excel workbook with multiple sheets:
- **Summary** — detected delimiters and overview
- **SegmentCounts** — frequency of each segment ID in both files + delta
- **IndexAlignment** — segments aligned by index with element columns
- **Differences** — long-form element-level diffs (respects ignored keys)
- **BySegmentBlocks** — concatenated blocks for visual inspection by segment ID

## Requirements
- Python 3.9+
- Install dependencies:
  ```bash
  pip install -r requirements.txt
  ```

## Usage
```bash
python compare_x12.py file1.txt file2.txt   --out x12_comparison.xlsx   --max_elems 20   --ignore "ISA13,ISA09,ISA10,GS06,ST02,SE02,GE02,IEA02"   --limit 0
```
**Flags**
- `--out`     : Output Excel file (default: `x12_comparison.xlsx`)
- `--max_elems`: Max elements per segment to compare (default: 20)
- `--ignore`  : Comma-separated keys to skip (e.g., `ISA13,GS06,ST02`)
- `--limit`   : Limit number of segments processed (0 = all)

**Notes**
- The tool tries to auto-detect delimiters from the ISA segment and falls back to heuristics.
- Works with both raw X12 (`~`/`*`) and line-based human-formatted files.
- Common volatile IDs (control numbers, dates) are ignored by default; adjust with `--ignore`.

## Examples
```bash
python compare_x12.py X12_Pattern.txt X12_Test.txt --out comparison.xlsx
```

## macOS tip (recommended)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python compare_x12.py file1 file2 --out report.xlsx
```

## Windows PowerShell tip
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python compare_x12.py file1 file2 --out report.xlsx
```

## Troubleshooting
- If Excel shows very long text columns, enable wrap and widen rows/columns as needed.
- If your right-hand file is a human-formatted view, element boundaries may be approximated.