import os
import sys
import re

def listfiles(folder):
    for root, folders, files in os.walk(folder):
        for filename in folders + files:
            yield os.path.join(root, filename)

if not os.path.isdir(sys.argv[1]):
    print('Give me apk folder argv[1]')
    sys.exit()
reports = [f for f in listfiles(sys.argv[1])]

for report in reports:
    apk_match = re.search("\.apk$", report)

    if apk_match:
        os.system("apktool d " + report + " --no-src -f -o " + report[:-4] )
