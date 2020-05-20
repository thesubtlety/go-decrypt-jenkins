# Go Decrypt Jenkins

This tools will try to automatically find and decrypt all the interesting bits from a jenkins backup folder.

Features:

* Decrypts newer and older Jenkins password formats
* Looks through all xml files for things that look encrypted
* Decrypts files encrypted in SecretBytes tags
* Supports additional Jenkins plugins with `-p`, e.g. `-p jenkins.security.ApiTokenProperty`
* Dumps user password hashes and tokens

```
% ./go-decrypt-jenkins -d jenkinsbackup/
scope: GLOBAL
id: 42e60ee3-fe19-4e3e-9eec-fec91e96e92e
username: jenkin
privateKey: -----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx5T0czKNmNkA7k0mbBJkl8hTLAzy...

scope: GLOBAL
id: al2e8dee-afe1-e3be-b5e1-7e797e9a9ede
username: admin
password: Password123
```

You can also specify the `credentials.xml`, `master.key`, and `hudson.util.Secret` manually.

```
% ./go-decrypt-jenkins -m master.key -s hudson.util.Secret -c credentials.xml
```

Be advised this is a bad project to learn go, so maybe don't run on a critical server.

