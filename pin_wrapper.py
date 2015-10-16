# Basic wrapper around pin

import os
import subprocess
import tempfile

def pin_cmd(tool, executable, stdin, temp_filename=None):
    if temp_filename is None:
        tf = tempfile.mkstemp()[1]
    else:
        tf = temp_filename
    # TODO: Auto-detect 32-bit executable and pass -p32
    proc = subprocess.Popen(['./pinbin', '-t', tool, '-o', tf, '--', executable], stdin=subprocess.PIPE, stdout=open('/dev/null','wb'), stderr=subprocess.STDOUT)
    proc.communicate(input=stdin)
    out = open(tf).read().split()
    if temp_filename is None: # Delete auto-generated files
        os.remove(tf)
    return out

def pin_thread(tool, executable, cases, out_dict):
    tmpf = tempfile.mkstemp()[1]

    for key, case in cases:
        out_dict[key] = pin_cmd(tool, executable, case, tempf)
