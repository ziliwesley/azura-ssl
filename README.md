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
azura-ssl sign-server --bits 4096 --subj "/CN=www.azura.com/C=CN/ST=Shanghai/L=Pudong District" --ca cert/azura-ca-root.crt --cakey cert/azura-ca-root.key --san cert/server
```

