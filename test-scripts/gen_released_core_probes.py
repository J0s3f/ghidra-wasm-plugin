"""Generate the semantic fixtures used to pin released-standard fixes in CI probes."""
import sys
from pathlib import Path
from released_core_fixtures import fixtures

target=Path(sys.argv[1]);target.mkdir(parents=True,exist_ok=True)
for name,data in fixtures().items():
    (target/name).write_bytes(data)
print(f'Released-core probes: {len(fixtures())}')
