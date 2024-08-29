import re
import sys

if len(sys.argv) != 3:
    print("Usage: python filter_changelog.py <changelog_file> <platform>")
    sys.exit(1)

changelog_file = sys.argv[1]
platform = sys.argv[2]

with open(changelog_file, "r") as f:
    lines = f.readlines()

for line in lines:
    match = re.search(r'^- @(\w+): ', line)
    if match:
        tag = match.group(1)
        if tag == "all" or tag == platform:
            print(re.sub(r'^- @(\w+): ', '- ', line).strip())
    else:
        print(line.strip())
