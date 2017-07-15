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
import { isString } from 'lodash';
import { pathExistsSync } from 'fs-extra';


import { readPrivateKey, readCertificate } from './cert.js';

inquirer.prompt.registerPrompt('path', PathPrompt);

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

            console.log(altNames);

            return [{
                name: 'subjectAltName',
                altNames
            }];
        });
}

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