import sys
import os
import subprocess
from time import sleep
import pexpect

action = sys.argv[1]
if action == "route":
    #python3 manage.py route interfaceName 53,989
    print("this argument is better run in a service")
    if len(sys.argv) < 4:
        print("Is mandatory netInteface and exlcuded port, separated by comma ex: 53,7300,8989")
        sys.exit(1)

    netInterface = sys.argv[2]
    portsArg = sys.argv[3]
    ports = [int(num) for num in portsArg.split(",")]
    ports = sorted(ports)
    start = 1
    for n in ports:
        if n == 1:
            start+1
            continue

        cmd = "iptables -t nat -I PREROUTING -i "+netInterface+" -p udp --dport "+str(start)+":"+str(n-1)+" -j REDIRECT --to-ports 8989"
        os.system(cmd)
        start = n+1    
    if ports[len(ports)-1] != 65535:
        cmd = "iptables -t nat -I PREROUTING -i "+netInterface+" -p udp --dport "+str(start)+":65535 -j REDIRECT --to-ports 8989"
        os.system(cmd)
    print("IPTABLES SUCESS")

if action == "manage":
    #python3 manage.py manage add user password 2028-05-01
    if len(sys.argv) < 3:
        print("Action user is requerid")
        sys.exit(1)
    if sys.argv[2] == "add":
        if len(sys.argv) < 6:
            print("Requerid user pass and expire time format 2022-05-01")  
            sys.exit(1)
            
        os.system("docker exec -it udpr adduser "+sys.argv[3]+" --disabled-password")    
        os.system("docker exec -it udpr chage -E "+sys.argv[5]+" "+sys.argv[3])
        cmdChangePassword = "docker exec -it udpr sh /root/useradd.sh \""+sys.argv[3]+"\" \""+sys.argv[4]+"\""
        os.system(cmdChangePassword)
      
        print("User added")
    if sys.argv[2] == "del":
        if len(sys.argv) < 4:
            print("Error requerid username to delete")
            sys.exit(1)
        print("delete user = "+sys.argv[3])
        os.system("docker exec -it udpr userdel "+sys.argv[3])
