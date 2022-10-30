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
reports = [f for f in os.listdir(sys.argv[1])]

if not os.path.isdir(sys.argv[2]):
    print('Give me apk folder argv[2]')
    sys.exit()
apks = [ f for f in os.listdir(sys.argv[2])]

if not os.path.isdir(sys.argv[3]):
    print('Give me rules folder argv[3]')
    sys.exit()

for filename in listfiles('./' + sys.argv[3]):
    match = re.search("\.yar$", filename)

    # if match is found
    if match:
        for report in reports:
            apkname = re.findall('(.*)-report',report)[0]
            if ' ' in report:
                apkname = '\''+apkname+'\''
                report = '\''+report+ '\''
            os.system('yara --no-warnings -x androguard='+ '/'.join([sys.argv[1],report]) + ' ' + filename + ' ' +'/'.join([sys.argv[2],apkname])) 
