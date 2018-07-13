'use strict';

const Util = require('util');
const Crypto = require('crypto');

const Algorithm = 'aes-256-gcm';
const Random = Util.promisify(Crypto.randomBytes);

module.exports = {

	random: Random,

	hasher: async function (data) {
		return Crypto.createHash('sha256').update(data).digest('hex');
	},

	encrypt: async function (password, text) {
		const vector = Crypto.randomBytes(16);
		const cipher = Crypto.createCipheriv(Algorithm, password, vector);

		let data = cipher.update(text, 'utf8', 'hex');
		data += cipher.final('hex');

		return data + ':' + vector;
	},

	decrypt: async function (password, text) {
		const texts = text.split(':');
		const decipher = Crypto.createDecipheriv(Algorithm, password, texts[1]);

		let data = decipher.update(texts[0], 'hex', 'utf8');
		data += cipher.final('utf8');
		
		return data;
	}

};
