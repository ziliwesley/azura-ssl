/**
 * src/ssl.js
 * 
 * provide wrapper functions to create and sign 
 * SSL certificates
 */
import { pki, md } from 'node-forge';
import Promise from 'bluebird';
import { isString } from 'lodash';
import { outputFile, readFile } from 'fs-extra';

const rsa = pki.rsa;

const generateKeyPair = (opts) => 
    Promise.fromCallback(callback => rsa.generateKeyPair(opts, callback));

const outputFileAsync = Promise.promisify(outputFile);
const readFileAsync = Promise.promisify(readFile);

// List of values accepted by openssl is documented at 
// https://www.openssl.org/docs/manmaster/man5/x509v3_config.html
// 
// For more info, see
// https://www.ibm.com/support/knowledgecenter/en/SSKTMJ_9.0.1/admin/conf_keyusageextensionsandextendedkeyusage_r.html
const CA_EXTENSION_SET = [{
    name: 'basicConstraints',
    critical: true,
    // The pathlen parameter indicates the maximum number of CAs that can 
    // appear below this one in a chain. So if you have a CA with a pathlen of zero it can only be used to sign end user certificates and not further CAs.
    // pathLenConstraint: 0,
    cA: true
}, {
    name: 'keyUsage',
    critical: true,
    digitalSignature: true,
    // nonRepudiation: true,
    // keyEncipherment: true,
    // dataEncipherment: true,
    // keyAgreement: true,
    keyCertSign: true,
    cRLSign: true
    // encipherOnly: true,
    // decipherOnly: true
}];

const SERVER_EXTENSION_SET = [{
    name: 'basicConstraints',
    critical: true,
    cA: false
}, {
    name: 'keyUsage',
    critical: true,
    digitalSignature: true,
    keyEncipherment: true
}, {
    name: 'extKeyUsage',
    critical: true,
    serverAuth: true,
    clientAuth: true
}];

/**
 * Save private key to the given path
 * @param  {PrivateKey} privateKey private key to be saved
 * @param  {string}     keyPath    path of the PEM format pk
 * @param  {string}     passphrase password used to encrypt the pk
 * @return {Promise}
 */
export function writePrivateKey(privateKey, keyPath, passphrase) {
    let pem = isString(passphrase) ?
        pki.encryptRsaPrivateKey(privateKey, passphrase, {
            // encrypts a Forge private key and outputs it in PEM format using OpenSSL's 
            // proprietary legacy format + encapsulated PEM headers (DEK-Info) 
            legacy: true,
            algorithm: '3des'
        }) :
        pem = pki.privateKeyToPem(privateKey);
    return outputFileAsync(keyPath, pem);
}

/**
 * Save certificate to the given path
 * @param  {Certificate} cert      certificate to be saved
 * @param  {string}      certPath  path of the PEM format certificate
 * @return {Promise}
 */
export function writeCertificate(cert, certPath) {
    return outputFileAsync(certPath, pki.certificateToPem(cert));
}

/**
 * Read certificate content from given path
 * @param  {string} certPath path of the PEM format certificate
 * @return {Promise}
 */
export function readCertificate(certPath) {
    return readFileAsync(certPath)
        .then(pem => pki.certificateFromPem(pem));
}

/**
 * Read private key info from given path
 * @param  {string} keyPath    path of the PEM format pk
 * @param  {string} passphrase password used to encrypt the pk
 * @return {Promise}    
 */
export function readPrivateKey(keyPath, passphrase) {
    return readFileAsync(keyPath)
        .then(pem => {
            if (isString(passphrase) && passphrase.length > 0) {
                let privateKey = pki.decryptRsaPrivateKey(pem, passphrase);

                if (privateKey) {
                    return privateKey
                }

                throw new Error(`Failed to decrypt private key, please check your passphrase.`);
            } else {
                return pki.privateKeyFromPem(pem);
            }
        });
}

/**
 * Create a certificate (unsigned)
 * @param  {Number} options.ttl    certificate Time-To-Live in years
 * @param  {Object} options.attrs  certificate subjects
 * @param  {[type]} options.exts   X.509 v3 certificate extensions
 * @param  {String} options.serial serial number of the certificate
 * @param  {[type]} options.bits   RSA key size
 * @return {Promise}
 */
export function createCertificate({
    ttl = 1, attrs, exts, serial = '02', bits}) {

    return generateKeyPair({ bits, workers: -1 })
        .then(({ privateKey, publicKey }) => {
            // To generate PEM format piravte key
            const cert = pki.createCertificate();

            cert.publicKey = publicKey;
            cert.serialNumber = serial;
            cert.validity.notBefore = new Date();
            cert.validity.notAfter = new Date();
            cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + ttl);
            cert.setSubject(attrs);
            cert.setExtensions(exts);

            return {
                privateKey,
                cert
            };
        });
}

/**
 * Self-sign a given certificate
 * @param  {Certificate} options.cert       the certificate to be signed
 * @param  {PrivateKey}  options.privateKey private key of the certificate
 * @return {Certificate}                    the certificate to be signed
 */
export function selfSign({ cert, privateKey }) {
    cert.setIssuer(cert.subject.attributes);
    cert.sign(privateKey);
}

/**
 * Use given CA to sign certificate
 * @param  {Certificate} options.cert   the certificate to be signed
 * @param  {PrivateKey}  options.CAKey  the private key of the CA
 * @param  {Certificate} options.CACert the certificate of the CA
 * @return {Certificate}                the certificate to be signed
 */
export function signCertificate({ cert, CAKey, CACert }) {
    cert.setIssuer(CACert.subject.attributes);
    // Signs the certificate using SHA-256 instead of SHA-1 
    cert.sign(CAKey, md.sha256.create());

    return cert;
}

export {
    CA_EXTENSION_SET,
    SERVER_EXTENSION_SET
}