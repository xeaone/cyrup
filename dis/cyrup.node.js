'use strict';

const Util = require('util');
const Crypto = require('crypto');
const Buffer = require('buffer');

const Algorithm = 'aes-256-gcm';
const Random = Util.promisify(Crypto.randomBytes);
const Pbkdf2 = Util.promisify(Crypto.pbkdf2);

module.exports = {

	random: Random,

	hasher: async function (data) {
		return Crypto.createHash('sha256').update(data).digest('hex');
	},

	encrypt: async function (password, text) {
		const vector = Crypto.randomBytes(16);
		const key = await Pbkdf2(password, vector, 137, 32, 'sha256');
		const cipher = Crypto.createCipheriv(Algorithm, key, vector);

		let data = cipher.update(text, 'utf8', 'hex');
		data += cipher.final('hex');

		return data + ':' + vector;
	},

	decrypt: async function (password, text) {
		const texts = text.split(':');
		const vector = texts[1];
		const key = await Pbkdf2(password, vector, 137, 32, 'sha256');
		const cipher = Crypto.createDecipheriv(Algorithm, key, vector);

		// FIXME: some error is happening

		let data = cipher.update(texts[0], 'hex', 'utf8');
		data += cipher.final('utf8');

		return data;
	}

};
