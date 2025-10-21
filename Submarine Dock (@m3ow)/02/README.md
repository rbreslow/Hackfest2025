# 02
In the description we are told that we should go deeper based on the information in the description of the first challenge.

So this hint tells us that we need some way to see the other docker containers. We can check the `/etc/hosts` file to see if there is any dns setup there. The only thing that tells us is that we are currently in `172.18.0.2`.
Using the original ping text box, we can try `172.18.0.3` and see that it is able to ping that service. We are able to do this all the way to `172.18.0.5`. We are also able to use `getent hosts` to find domains for the services. So we can do `getent hosts 172.18.0.3` to see that it is called `submarine-api` which is running on port 5000, and `172.18.0.4` is `submarine-sonar` running ssh.

The first `flag.txt` also now contained a hint, which said to try `/view` on the api. 

So we tried with `/view?file=flag.txt` which returned the second flag: `HF-PqIXoOkBksjLqnowOUVELCeJwHxafHCp`.