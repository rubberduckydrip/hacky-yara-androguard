import os
import sys

def trimmed(path):
    return os.path.basename(path)

to_scan = sys.argv[1]
rules = sys.argv[2]
output = sys.argv[3]

tags = ["collection", "defense_evasion", "impact", "persistence", "c2"]

for tag in tags:
    cmd = f"yara -t {tag} {rules} -r {to_scan} > {os.path.join(output, f'{trimmed(to_scan)}_{tag}.txt')}"
    print(f"Running command: {cmd}")
    os.system(cmd)
