// 
// "sign-server" command
// Generate self-signed CA certificates
// 
// ```bash
// azura-ssl sign-server [filename]
// ```

import inquirer from 'inquirer';
import { PathPrompt } from 'inquirer-path';
import chalk from 'chalk';
import { isString, isArray } from 'lodash';
import { pathExistsSync } from 'fs-extra';


import { readPrivateKey, readCertificate } from './cert.js';

inquirer.prompt.registerPrompt('path', PathPrompt);

/**
 * Guide the user to enter the path of CA private key
 * @return {Promise}
 */
export function getCAPrivateKey(keyPath) {
    const questions = [{
        name: 'keyPath',
        type: 'path',
        message: 'Enter the path of CA private key',
        default: process.cwd(),
        when: !isString(keyPath)
    }, {
        name: 'passphrase',
        message: 'Enter the passphrase used to encrypt the private key',
        type: 'password'
    }];

    return inquirer.prompt(questions)
        .then(anwsers => {
            const confirmedPath = anwsers.keyPath || keyPath;

            if (!pathExistsSync(confirmedPath)) {
                throw new Error(`Can not locate the CA private key: ${confirmedPath}`);
            }

            return readPrivateKey(confirmedPath, anwsers.passphrase);
        })
        .catch(err => {
            console.log(chalk.red(`\n${err}\n`));

            return getCAPrivateKey();
        });
}

/**
 * Guide the user to enter the path of CA certificate
 * @return {Promise}
 */
export function getCACertificate(crtPath) {
    const questions = [{
        name: 'crtPath',
        type: 'path',
        message: 'Enter the path of CA certificate',
        default: process.cwd(),
        when: !isString(crtPath)
    }];

    return inquirer.prompt(questions)
        .then(anwsers => {
            const confirmedPath = anwsers.crtPath || crtPath;

            if (!pathExistsSync(confirmedPath)) {
                throw new Error(`Can not locate the CA certificate: ${confirmedPath}`);
            }

            return readCertificate(confirmedPath);
        })
        .catch(err => {
            console.log(chalk.red(`\n${err}\n`));

            return getCAPrivateKey();
        });
}


/**
 * Parse OpenSSL oneline distinguished name string
 * @see https://github.com/kjur/jsrsasign/blob/a7fdf19656ea761187956d0db9fd34116532f03e/src/asn1x509-1.0.js#L1392
 * @param  {string} dnStr distinguished name by string (ex. /C=US/O=aaa)
 * @return {Array}        array of subject attributes
 */
export function parseAttrsFromString(dnStr) {
    let attrs = [];
    let pairs = dnStr.split('/');
    pairs.shift();
    
    pairs.forEach(pair => {
        let matchResult = pair.match(/^([^=]+)=(.+)$/);
        if (matchResult) {
            attrs.push({
                shortName: matchResult[1],
                value: matchResult[2]
            });
        } else {
            throw `Subjects malformed: ${pair}`;
        }
    });

    return attrs;
}


/**
 * Guide the user to enter a passphrase to encrypt the generated private key
 * @return {Promise}
 */
export function getPassphrase() {
    const questions = [{
        name: 'passphrase',
        // Enter a passphrase you wish to encrypt the generated CA private key (Leave blank if you do not want to have one)
        message: 'Enter a passphrase',
        type: 'password'
    }, {
        name: 'passphraseConfirm',
        message: 'Enter the passphrase again to confirm',
        type: 'password',
        when: (anwsers) => anwsers.passphrase !== ''
    }];

    return inquirer.prompt(questions)
        .then(anwsers => {
            if (anwsers.passphrase === '') {
                return anwsers.passphrase;
            }

            if (anwsers.passphrase === anwsers.passphraseConfirm) {
                return anwsers.passphrase;
            }

            console.log(chalk.red('\nPassphrase not match, please enter again.\n'));

            return getPassphrase();
        });
}

/**
 * Guide the user to enter subjects for certificate request
 * @param  {?string} predefinedAttrs distinguished name by string
 * @return {Promise}
 */
export function getSubjects(predefinedAttrs) {
    if (isArray(predefinedAttrs) && predefinedAttrs.length > 0) {
        //  Subjects are already defined by OpenSSL one-line 
        //  distinguished name string
        return Promise.resolve(predefinedAttrs);
    }

    const questions = [{
        name: 'countryName',
        message: 'Country [C]'
    }, {
        name: 'organizationName',
        message: 'Organization [O]'
    }, {
        name: 'organizationalUnitName',
        message: 'Organization Unit [OU]'
    }, {
        name: 'commonName',
        message: 'Common Name [CN]'
    }];

    // Ask user to enter subjects
    return inquirer.prompt(questions)
        .then(anwsers => {
            const attrs = [];

            for (let key in anwsers) {
                let prop = anwsers[key];

                if (prop !== '') {
                    attrs.push({
                        name: key,
                        value: prop
                    });
                }
            }

            return attrs;
        });
}


/**
 * Guide the user to specify a list of "SAN(subject alt names)"
 * @see  https://www.openssl.org/docs/manmaster/man5/x509v3_config.html#Subject-Alternative-Name
 * @return {Array}   Array of X.509 V3 Certificate Extension
 */
export function getSAN() {
    const questions = [{
        name: 'uris',
        message: 'Enter a list of alternative URIs (e.g. "a.com, b.com")',
        default: 'localhost'
    }, {
        name: 'ips',
        message: 'Enter a list of alternative IPs (e.g. "192.168.2.3, 10.0.0.6")',
        default: '127.0.0.1'
    }];

    return inquirer.prompt(questions)
        .then(anwsers => {
            const altNames = [];

            anwsers.uris
                .replace(' ', '')
                .split(',')
                .forEach(uri => altNames.push({
                    type: 6,
                    value: uri
                }));

            anwsers.ips
                .replace(' ', '')
                .split(',')
                .forEach(ip => altNames.push({
                    type: 7,
                    ip
                }));

            return [{
                name: 'subjectAltName',
                altNames
            }];
        });
}