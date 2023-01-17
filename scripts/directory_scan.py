import os
import sys
import re

def listfiles(folder):
    for root, folders, files in os.walk(folder):
        for filename in folders + files:
            yield os.path.join(root, filename)

if not os.path.isdir(sys.argv[1]):
    print('Give me report folder argv[1]')
    sys.exit()
reports = [f for f in listfiles(sys.argv[1])]

if not os.path.isdir(sys.argv[2]):
    print('Give me rules folder argv[2]')
    sys.exit()

for filename in listfiles('./' + sys.argv[2]):
    match = re.search("\.yar$", filename)

    # if match is found
    if match:
        rule_count = 0
        for report in reports:
            os.system('yara --no-warnings '+ filename + ' ' + report)
            #print("Scanning rule: " + filename + " against: " + report)
            rule_count++

    print("Num of rules scanned: " + rule_count)
