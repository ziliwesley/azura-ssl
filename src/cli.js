import program from 'commander';
import chalk from 'chalk';
import path from 'path';

import {
    selfSign,
    createCertificate,
    createP12Archive,
    signCertificate,
    writePrivateKey,
    writeCertificate,
    writeP12Archive,
    CA_EXTENSION_SET,
    SERVER_EXTENSION_SET,
    CLIENT_EXTENSION_SET } from './cert.js';
import {
    parseAttrsFromString,
    getCAPrivateKey,
    getCACertificate,
    getSAN,
    getPassphrase,
    getSubjects } from './sign.js';

const VERSION = '0.1.0';
const currentPath = process.cwd();

program
    .version(VERSION);

// ```bash
// azura-ssl sign-ca [filename]
// ```
// By default, a password will be asked to encrypt the generated
// private key using triple DES
program
    .command('sign-ca [filename]')
    .description('generate self-signed CA certificate.')
    .option('-b, --bits <size>', 'RSA key size (Default: 2048)', parseInt)
    .option('-s, --subj <attrs>', 'set request subjects (Format: "/t0=v0/t1=v1")', parseAttrsFromString)
    .action(function (filename = 'ca', options) {
        const rsaSize = options.bits || 2048;
        const fullpath = path.resolve(currentPath, filename);
        // Trim file extension (e.g: .crt) from given filename
        const basePath = fullpath.replace(path.extname(fullpath), '');
        const keyPath = `${basePath}.key`;
        const certPath = `${basePath}.crt`;
        let passphrase;
        let attrs;

        return getPassphrase()
            .then((result) => {
                passphrase = result;

                return getSubjects(options.subj);
            })
            .then((result) => {
                attrs = result;

                return createCertificate({
                    passphrase,
                    serial: '01',
                    bits: rsaSize,
                    ttl: 2,
                    attrs,
                    exts: CA_EXTENSION_SET
                });
            })
            .then(({ privateKey, cert }) => {
                // Finally self-sign
                selfSign({
                    cert,
                    privateKey
                });

                return Promise.all([
                    writePrivateKey(privateKey, keyPath, passphrase),
                    writeCertificate(cert, certPath)
                ]);
            })
            .then(() => {
                console.log('CA certificate created:');
                console.log(chalk.green(keyPath));
                console.log(chalk.green(certPath));
            })
            .catch(err => {
                console.log(chalk.red(err));
            });
    });


// ```bash
// azura-ssl sign-server <filename>
// ```
// 
// equivalent commands using openSSL:
// ```bash
// openssl req -newkey rsa:<bits> -nodes -keyout <filename>.key -out <filename>.csr
// openssl x509 -req -in <filename>.csr -ca <CAPath> -cakey <CAKeyPath> -days 365 -out <filename>.crt
// ```
program
    .command('sign-server <filename>')
    .description('generate self-signed CA certificate.')
    .option('--ca <CAPath>', 'specifies the CA certificate to be used for signing')
    .option('--cakey <CAKeyPath>', 'sets the CA private key to sign a certificate with')
    .option('--san', 'whether to add "subjectAltName" field or not')
    .option('-c, --bits <size>', 'RSA key size (Default: 2048)', parseInt)
    .option('-s, --subj <attrs>', 'set request subjects (Format: "/t0=v0/t1=v1")', parseAttrsFromString)
    .action(function (filename, options) {
        const rsaSize = options.bits || 2048;
        const fullpath = path.resolve(currentPath, filename);
        // Trim file extension (e.g: .crt) from given filename
        const basePath = fullpath.replace(path.extname(fullpath), '');
        const keyPath = `${basePath}.key`;
        const certPath = `${basePath}.crt`;
        let CAKey, CACert, attrs;

        return getCAPrivateKey(options.cakey)
            .then(result => {
                // CA private key loaded
                CAKey = result;
                return getCACertificate(options.ca);
            })
            .then(result => {
                CACert = result;
                return getSubjects(options.subj);
            })
            .then(result => {
                attrs = result;

                if (options.san) {
                    return getSAN();
                } else {
                    return [];
                }
            })
            .then(result => {
                return createCertificate({
                    attrs,
                    exts: SERVER_EXTENSION_SET.concat(result),
                    serial: '02',
                    ttl: 3,
                    bits: rsaSize
                });
            })
            .then(({ privateKey, cert }) => {
                // Use CA's private key to sign server certificate
                signCertificate({
                    cert,
                    CAKey,
                    CACert
                });
                
                return Promise.all([
                    writePrivateKey(privateKey, keyPath),
                    writeCertificate(cert, certPath)
                ]);
            })
            .then(() => {
                console.log('Server certificate created:');
                console.log(chalk.green(keyPath));
                console.log(chalk.green(certPath));
            })
            .catch(err => {
                console.log(chalk.red(err));
            });
    });

// ```bash
// azura-ssl sign-client <filename>
// ```
// 
// equivalent commands using openSSL:
// ```bash
// openssl req -newkey rsa:<bits> -nodes -keyout <filename>.key -out <filename>.csr
// openssl x509 -req -in <filename>.csr -ca <CAPath> -cakey <CAKeyPath> -days 365 -out <filename>.crt
// openssl pkcs12 -export -in <filename>.crt -inkey <filename>.key -certfile <CAPath> -name "Wesley W." -out <filename>.p12
// ```
program
    .command('sign-client <filename>')
    .description('generate self-signed CA certificate.')
    .option('--ca <CAPath>', 'specifies the CA certificate to be used for signing')
    .option('--cakey <CAKeyPath>', 'sets the CA private key to sign a certificate with')
    .option('--name <friendlyName>', 'specifies the "friendly name"')
    .option('-c, --bits <size>', 'RSA key size (Default: 2048)', parseInt)
    .option('-s, --subj <attrs>', 'set request subjects (Format: "/t0=v0/t1=v1")', parseAttrsFromString)
    .action(function (filename, options) {
        const rsaSize = options.bits || 2048;
        const fullpath = path.resolve(currentPath, filename);
        // Trim file extension (e.g: .crt) from given filename
        const basePath = fullpath.replace(path.extname(fullpath), '');
        const keyPath = `${basePath}.key`;
        const certPath = `${basePath}.crt`;
        const p12Path = `${basePath}.p12`;
        let CAKey, CACert, attrs, passphrase;

        return getCAPrivateKey(options.cakey)
            .then(result => {
                // CA private key loaded
                CAKey = result;
                return getCACertificate(options.ca);
            })
            .then(result => {
                CACert = result;
                return getSubjects(options.subj);
            })
            .then(result => {
                attrs = result;

                console.log('\nPlease provide a password to encrypt the PKCS#12 archive file.\n');

                return getPassphrase();
            })
            .then(result => {
                passphrase = result

                return createCertificate({
                    attrs,
                    exts: CLIENT_EXTENSION_SET,
                    serial: '03',
                    ttl: 3,
                    bits: rsaSize
                });
            })
            .then(({ privateKey, cert }) => {
                // Use CA's private key to sign server certificate
                signCertificate({
                    cert,
                    CAKey,
                    CACert
                });

                // Generate PKCS#12 archive
                const p12 = createP12Archive({
                    privateKey,
                    cert,
                    passphrase,
                    CACert,
                    friendlyName: options.name
                });
                
                return Promise.all([
                    writePrivateKey(privateKey, keyPath),
                    writeCertificate(cert, certPath),
                    writeP12Archive(p12, p12Path)
                ]);
            })
            .then(() => {
                console.log('Client certificate created:');
                console.log(chalk.green(keyPath));
                console.log(chalk.green(certPath));
                console.log(chalk.green(p12Path));
            })
            .catch(err => {
                console.log(chalk.red(err));
                console.error(err);
            });
    });

program.parse(process.argv);
