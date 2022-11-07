import os
import sys
import re

def listfiles(folder):
    for root, folders, files in os.walk(folder):
        for filename in folders + files:
            yield os.path.join(root, filename)

for filename in listfiles('./' + sys.argv[1]):
    match = re.search("\.yar$", filename)

    # if match is found
    if match:
        print("Rule: " + filename)
