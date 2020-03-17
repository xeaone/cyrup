import babel from 'rollup-plugin-babel';

import {
    name, email, author, license, version
} from'./package.json';

const banner = `
/*
    Name: ${name}
    Version: ${version}
    License: ${license}
    Author: ${author}
    Email: ${email}
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/
`;

export default [
    {
        input: 'src/cyrup.js',
        output: {
            banner,
            format: 'es',
            indent: '    ',
            file: 'dst/cyrup.js'
        }
    },
    {
        input: 'src/cyrup.js',
        output: {
            banner,
            format: 'es',
            indent: '    ',
            file: 'dst/cyrup.min.js'
        },
        plugins: [ babel({ presets: [ 'minify' ], comments: false }) ]
    }
];
