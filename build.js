
const Cp = require('child_process');
const Mp = Cp.execSync('npm root -g').toString().trim();
const Muleify = require(`${Mp}/muleify`);

const Package = require('./package');
const Util = require('util');
const Fs = require('fs');

const ReadFile = Util.promisify(Fs.readFile);
const WriteFile = Util.promisify(Fs.writeFile);

const name = Package.name;
const email = Package.email;
const author = Package.author;
const license = Package.license;
const version = Package.version;

const header = `/*
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

const prepend = async function (data, path) {
	const fileData = await ReadFile(path, 'utf8');
	await WriteFile(path, data + fileData, 'utf8');
};

(async function () {

	const options = {
		bundle: true,
		transpile: true,
	};

	await Muleify.pack(`src/${name}.js`, `dis/${name}.js`, options);
	await prepend(header, `dis/${name}.js`);

	options.minify = true;

	await Muleify.pack(`src/${name}.js`, `dis/${name}.min.js`, options);
	await prepend(header, `dis/${name}.min.js`);

}()).catch(function (error) {
	console.error(error);
});
