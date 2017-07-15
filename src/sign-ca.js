// 
// "sign-ca" command
// Generate self-signed CA certificates
// 
// ```bash
// azura-ssl sign-ca [filename]
// ```

import inquirer from 'inquirer';
import chalk from 'chalk';
import { isArray } from 'lodash';

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