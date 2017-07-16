# azura-ssl

a `azura-ssl` is a utility tool:

- enabled by [`node-forge`](https://github.com/jprichardson/node-fs-extra), therefore does not require [`openSSL`](https://www.openssl.org/)
- to rovide quick and easy command line tool to manage **self-signed** certificates.

## Commmand Line Usage

### Generate self-signed CA certificates

Basic usage:

```bash
azura-ssl sign-ca
```

With options:

```bash
# Generate a self-signed root ca at:
# ./cert/azura-ca-root.key (private key)
# ./cert/azura-ca-root.crt (certificate signed)
azura-ssl sign-ca --bits 4096 --subj "/CN=ABC CA/C=CN/ST=Shanghai/L=Pudong District" cert/azura-ca-root
```

### Generate server certificates

Basic usage:

```bash
azura-ssl sign-server <filename>
```

With options:

```bash
# Generate a server certificate at:
# ./cert/server.key (private key)
# ./cert/server.crt (certificate signed)
azura-ssl sign-server --bits 2048 --subj "/CN=www.azura.com/C=CN/ST=Shanghai/L=Pudong District" --ca cert/azura-ca-root.crt --cakey cert/azura-ca-root.key --san cert/server
```

### Generate client certificate

Basic usage:

```bash
azura-ssl sign-client <filename>
```

With options:

```bash
# Generate a client certificate at:
# ./cert/client.key (private key)
# ./cert/client.crt (certificate signed)
# ./cert/client.p12 (p12 archive)
azura-ssl sign-client --bits 2048 --subj "/CN=Wesley/C=CN/ST=Shanghai" --ca cert/azura-ca-root.crt --cakey cert/azura-ca-root.key --name "Zili Wesley" cert/client
```
