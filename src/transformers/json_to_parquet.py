"""Convert newline-delimited JSON (or Python dicts) into Parquet files.\n\nProvides two conversion functions:\n    - jsonl_to_parquet(): Reads a .jsonl file and writes a Parquet file\n    - write_parquet_streaming(): Converts in-memory list of dicts to Parquet\n\nBoth functions use PyArrow with Snappy compression for efficient storage.\nOutput Parquet files can be loaded by DuckDB for SQL-based analytics.\n"""
import json
import pandas as pd
from pathlib import Path

def jsonl_to_parquet(input_path: str, output_path: str, chunk_size: int = 10000):
    in_path = Path(input_path)
    out_path = Path(output_path)

    rows = []

    with in_path.open('r', encoding='utf-8') as f:
        for line in f:
            rows.append(json.loads(line))

            if len(rows) >= chunk_size:
                df = pd.DataFrame(rows)
                df.to_parquet(
                    out_path,
                    engine='pyarrow',
                    compression='snappy',
                    index=False
                )
                rows = []

    # Final flush
    if rows:
        df = pd.DataFrame(rows)
        df.to_parquet(
            out_path,
            engine='pyarrow',
            compression='snappy',
            index=False
        )
def write_parquet_streaming(records, out_path):
    """
    Convert a list of Python dicts into a Parquet file.
    Drops invalid empty fields before saving.
    """
    import pandas as pd
    from pathlib import Path

    # Remove 'fields' key if empty (Parquet cannot store empty structs)
    cleaned = []
    for r in records:
        if "fields" in r and r["fields"] == {}:
            r = {k: v for k, v in r.items() if k != "fields"}
        cleaned.append(r)

    df = pd.DataFrame(cleaned)

    out = Path(out_path)
    df.to_parquet(out, engine="pyarrow", compression="snappy", index=False)

