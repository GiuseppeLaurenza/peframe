import subprocess

def analysis(sample_file_path):
    cmd = ["../nucleus/nucleus", "-d", "linear", "-D", "-f", "-e", sample_file_path ]
    process = subprocess.Popen(cmd,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    # wait for the process to terminate
    out, err = process.communicate()
    errcode = process.returncode
    nucleus_result = out.splitlines()
    list_size = []
    for i in nucleus_result:
        try:
            value = int(i.decode("utf-8").split("\t")[1])
        except:
            value=0
        list_size.append(value)
    return list_size