import subprocess

proc = subprocess.Popen('kubectl get pods -o wide | awk "{ print $6 }"',
        shell=True, stdout=subprocess.PIPE, encoding='utf8')
stdout_value = proc.communicate()[0]
for ipaddress in stdout_value.split('\n'):
    print(ipaddress)
