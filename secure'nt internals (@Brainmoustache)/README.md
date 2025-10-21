# secure'nt internals

## Flag 01

On the challenge provisioning page, we received an AWS access key and website URL. The website's HTML source code includes a link to an S3 bucket.

```console
[MacBook-Pro ~] (13s)$ export AWS_PROFILE=securent            
[MacBook-Pro ~]$ aws sts get-caller-identity            
{
    "UserId": "AIDASECYGINV2XHRMGODQ",
    "Account": "146213847915",
    "Arn": "arn:aws:iam::146213847915:user/y1dk85-user"
}
```

```html
<section id="home" class="hero">
    <div class="hero-content">
        <h2>secure'nt</h2>
        <p>Fortifying Your Home Network with DIY Cyber Solutions</p>
        <a href="#services" class="cta-button">Explore My Lab</a>
        <br>
        <br>
        <!-- y1dk85-website.s3.us-west-2.amazonaws.com/ -->
    </div>
</section>
```

```console
[MacBook-Pro ~]$ aws s3 ls s3://y1dk85-website          
                           PRE admin/
                           PRE restricted_content
[MacBook-Pro ~]$ aws s3 ls s3://y1dk85-website/restricted_content/
2025-10-16 19:38:53        247 ca.crt
2025-10-16 19:38:53         40 flag.txt
2025-10-16 19:38:53        607 operator-conf.yaml
2025-10-16 19:38:53        312 operator.crt
2025-10-16 19:38:53        127 operator.key
```

In `flag.txt`:

```
HF-c3df32be-33a3-4ca6-8f25-5d966f0c5f31
```

🚩

## Flag 02

We found configuration files for [Nebula: Open Source Overlay Networking](https://nebula.defined.net/docs/). Nebula looks similar to Tailscale. 

The private key appears to be in the `operator` group:

```console
[MacBook-Pro nebula]$ nebula-cert print -path operator.crt 
NebulaCertificate {
	Details {
		Name: operator
		Ips: [
			10.13.37.11/24
		]
		Subnets: []
		Groups: [
			"operator"
		]
		Not before: 2025-10-17 05:49:58 +0200 CEST
		Not After: 2026-10-17 05:49:57 +0200 CEST
		Is CA: false
		Issuer: 91f4012f13bcc65b33d55ea16661f3f8a0992c16d283c576496f3f60643fbc12
		Public key: f1eca932b47f025a0ff0dd86744310dffb39bd84aaa523a4e9f20590119b1142
		Curve: CURVE25519
	}
	Fingerprint: 1b2f1ad7a3e83c8d2f7a73baa360325105a09c7aa2739c3ba50afb7f5f198b04
	Signature: d5d26b9e247956b158257ea2647a014412ba8799c1c062877cca7c12a0ed2c24ff9611617d892c08347264fbaecd1155cb94d9c65d96790245e036e31b309e0b
}
```

Handshakes in the Nebula logs reveal the existence of a few hosts, and nmap finds an HTTP service running on `home-pc`:

```console
INFO[0765] Handshake message received                    certName=home-pc durationNs=334577666 fingerprint=59423139a8b1477d165976cffb2753a03a6ba6bb09365b53e14daf536e50265f handshake="map[stage:2 style:ix_psk0]" initiatorIndex=2436728177 issuer=91f4012f13bcc65b33d55ea16661f3f8a0992c16d283c576496f3f60643fbc12 remoteIndex=2436728177 responderIndex=2499735836 sentCachedPackets=1 udpAddr="44.244.212.27:4242" vpnIp=10.13.37.2
```

- `lighthouse` - 10.13.37.3
- `home-pc` - 10.13.37.2
- `dev-pc` - 10.13.37.12
- `vault-pc` - 10.13.37.13

We connect to the HTTP service in `home-pc,` which is a file server, and can get an SSH key we use to log in. From there, `.bash_history` shows the updated `root` user password, which is `WZnKEUBE1G`.

`su root` and find the flag in the home directory.

🚩

## The Search for Flag 03

We never found Flag 03. We discovered that `home-pc` was running Nebula with a different user group that had network access to `dev-pc`:

```console
[MacBook-Pro home-pc-nebula]$ nebula-cert print -path host.crt         
NebulaCertificate {
	Details {
		Name: home-pc
		Ips: [
			10.13.37.2/24
		]
		Subnets: []
		Groups: [
			"home"
		]
		Not before: 2025-10-17 05:49:58 +0200 CEST
		Not After: 2026-10-17 05:49:57 +0200 CEST
		Is CA: false
		Issuer: 91f4012f13bcc65b33d55ea16661f3f8a0992c16d283c576496f3f60643fbc12
		Public key: bc5c7fdb5dc169fdccd9a31b0a67f42bda2a583170786639398276a413877e2e
		Curve: CURVE25519
	}
	Fingerprint: 59423139a8b1477d165976cffb2753a03a6ba6bb09365b53e14daf536e50265f
	Signature: ea5990ec23729020a400dc09b32801b78cf7d47d557308d24a29411ae7ccd22695faa38d6ad3317cdb9a3db441c139c46687e305614cef19102626163d2b7e0c
}
```

We could hit an SSH server on `dev-pc`, but couldn't figure out how to sign in.
