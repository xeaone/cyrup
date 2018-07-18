(function (global, factory) {
	typeof exports === 'object' && typeof module !== 'undefined' ? module.exports = factory() :
	typeof define === 'function' && define.amd ? define('Cyrup', factory) :
	(global.Cyrup = factory());
}(this, (function () { 'use strict';

	const Cyrup = {

		ROUNDS: 99999,
		ENCODING: 'hex',

		SALT_BYTES: 16,
		HASH_BYTES: 32,
		VECTOR_BYTES: 12,
		SECRET_BYTES: 48,

		secret (data) {
			const self = this;

			data = data || {};
			data.size = data.size || self.SECRET_BYTES;

			return Promise.resolve().then(function () {
				return self.randomBytes(data.size);
			}).then(function (buffer) {
				return self.bufferToHex(buffer);
			});
		},

		hash (data) {
			const self = this;

			data = data || {};
			data.type = data.type || self.HASH_TYPE;

			return Promise.resolve().then(function () {
				return self.stringToBuffer(data.text);
			}).then(function (buffer) {
				return self.createHash(buffer, data.type);
			}).then(function (buffer) {
				return self.bufferToHex(buffer);
			});
		},

		encrypt (password, text, data) {
			const self = this;

			if (!text) throw new Error('text required');
			if (!password) throw new Error('password required');

			data = data || {};
			data.rounds = data.rounds || self.ROUNDS;
			// data.encoding = data.encoding || self.ENCODING;
			data.hashType = data.hashType || self.HASH_TYPE;
			data.algorithm = data.algorithm || self.ALGORITHM;
			data.hashBytes = data.hashBytes || self.HASH_BYTES;
			data.saltBytes = data.saltBytes || self.SALT_BYTES;
			data.vectorBytes = data.vectorBytes || self.VECTOR_BYTES;

			let bSalt, bVector, bText, bPassword;

			return Promise.all([
				self.stringToBuffer(text),
				self.stringToBuffer(password),
				self.randomBytes(data.saltBytes),
				self.randomBytes(data.vectorBytes)
			]).then(function (items) {
				bText = items[0];
				bSalt = items[2];
				bVector = items[3];
				bPassword = items[1];
			}).then(function () {
				return self.pbkdf2(bPassword, bSalt, data.rounds, data.hashType, data.algorithm)
			}).then(function (key) {
				return self._encrypt(data.algorithm, key, bVector, bText);
			}).then(function (bEncrypted) {
				return Promise.all([
					self.bufferToHex(bEncrypted),
					self.bufferToHex(bVector),
					self.bufferToHex(bSalt),
				]).then(function (results) {
					return results.join(':');
				});
			});
		},

		decrypt (password, encrypted, data) {
			const self = this;

			if (!password) throw new Error('password required');
			if (!encrypted) throw new Error('encrypted required');

		 	const self = this;
			const encrypteds = encrypted.split(':');
			const textHex = encrypteds[0];
			const vectorHex = encrypteds[1];
			const saltHex = encrypteds[2];

			let passwordBuffer, textBuffer, vectorBuffer, saltBuffer;

			data = data || {};
			data.rounds = data.rounds || self.ROUNDS;
			// data.encoding = data.encoding || self.ENCODING;
			data.hashType = data.hashType || self.HASH_TYPE;
			data.algorithm = data.algorithm || self.ALGORITHM;
			data.hashBytes = data.hashBytes || self.HASH_BYTES;

			return Promise.all([
				self.hexToBuffer(textHex),
				self.hexToBuffer(saltHex),
				self.hexToBuffer(vectorHex),
				self.stringToBuffer(password)
			]).then(function (items) {
				textBuffer = items[0];
				saltBuffer = items[1];
				vectorBuffer = items[2];
				passwordBuffer = items[3];
			}).then(function () {
				return self.pbkdf2(passwordBuffer, saltBuffer, data.rounds, data.hashType, data.algorithm);
			}).then(function (key) {
				return self._decrypt(data.algorithm, key, vectorBuffer, textBuffer);
			}).then(function (decrypted) {
				return self.bufferToString(decrypted);
			});
		}

	};

	if (typeof window === 'undefined') {

		const Util = require('util');
		const Crypto = require('crypto');

		Cyrup.HASH_TYPE = 'sha512';
		Cyrup.ALGORITHM = 'aes-256-gcm';

		Cyrup.hexToBuffer = async function (hex) {
			return Buffer.from(hex, 'hex');
		};

		Cyrup.bufferToHex = async function (buffer) {
			return buffer.toString('hex');
		};

		Cyrup.stringToBuffer = async function (string) {
			return Buffer.from(string, 'utf8');
		};

		Cyrup.bufferToString = async function (buffer) {
			return buffer.toString('utf8');
		};

		Cyrup.randomBytes = Util.promisify(Crypto.randomBytes);

		Cyrup.createHash = async function (buffer, type) {
			return Crypto.createHash(type).update(buffer).digest();
		};

		Cyrup.pbkdf2 = Util.promisify(Crypto.pbkdf2);

		Cyrup._encrypt = async function (algorithm, key, vector, text) {
			const self = this;
			const cipher = Crypto.createCipheriv(algorithm, key, vector);
			const encrypted = cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
			const tag = cipher.getAuthTag();
			console.log(self.bufferToString(tag));
			return encrypted;
		};

		Cyrup._decrypt = async function (algorithm, key, vector, text) {
			const self = this;
			const decipher = Crypto.createDecipheriv(algorithm, key, vector);
			// decipher.setAuthTag(tag);
			const decrypted = decipher.update(text, 'hex', 'utf8') + decipher.final('utf8');
		};

	} else {

		Cyrup.HASH_TYPE = 'SHA-512';
		Cyrup.ALGORITHM = 'AES-GCM';

		Cyrup.hexToBuffer = function (hex) {
			return Promise.resolve().then(function () {

				if (typeof hex !== 'string') {
					throw new TypeError('Expected input to be a string');
				}

				if ((hex.length % 2) !== 0) {
					throw new RangeError('Expected string to be an even number of characters');
				}

				let bytes = new Uint8Array(hex.length / 2);

				for (let i = 0, l = hex.length; i < l; i += 2) {
					bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
				}

				return bytes.buffer
			});
		};

		Cyrup.bufferToHex = function (buffer) {
			return Promise.resolve().then(function () {
				let bytes = new Uint8Array(buffer);
				let hexes = [];

				for (let i = 0, l = bytes.length; i < l; i++) {

					let hex = bytes[i].toString(16);
					let pad = ('00' + hex).slice(-2);

					hexes.push(pad);
				}

				return hexes.join('');
			});
		};

		Cyrup.stringToBuffer = function (string) {
			return Promise.resolve().then(function () {
				let bytes = new Uint8Array(string.length);

				for (let i = 0, l = string.length; i < l; i++) {
					bytes[i] = string.charCodeAt(i);
				}

				return bytes.buffer
			});
		};

	    Cyrup.bufferToString = function (buffer) {
			return Promise.resolve().then(function () {
		        let data = '';
				let bytes = new Uint8Array(buffer);

		        for (let i = 0, l = bytes.length; i < l; i++) {
					data += String.fromCharCode(bytes[i]);
		        }

		        return data;
			});
	    };

		Cyrup.randomBytes = function (size) {
			return Promise.resolve().then(function () {
				return window.crypto.getRandomValues(new Uint8Array(size));
			});
		};

		Cyrup.createHash = function (buffer, type) {
			return Promise.resolve().then(function () {
				return window.crypto.subtle.digest(type, buffer);
			});
		};

		Cyrup.pbkdf2 = function (password, salt, iterations, length, digest, algorithm) {
			const self = this;
			return Promise.resolve().then(function () {
				if (!salt) throw new Error('salt required');
				if (!length) throw new Error('length required');
				if (!digest) throw new Error('digest required');
				if (!password) throw new Error('password required');
				if (!iterations) throw new Error('iterations required');
			}).then(function () {
				return window.crypto.subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']);
			}).then(function (key) {
				return window.crypto.subtle.deriveKey({
					salt: salt,
					name: 'PBKDF2',
					hash: digest || 'SHA-512',
					iterations: iterations || self.ROUNDS
				}, key, {
					length: length || 256,
					name: algorithm || 'AES-GCM'
				}, false, ['encrypt', 'decrypt']);
			});
		};

		Cyrup._encrypt = function (algorithm, key, vector, text) {
			return Promise.resolve().then(function () {
				return window.crypto.subtle.encrypt({ name: algorithm, iv: vector }, key, text);
			});
		};

		Cyrup._decrypt = function (algorithm, key, vector, text) {
			return Promise.resolve().then(function () {
				return window.crypto.subtle.decrypt({ name: algorithm, iv: vector }, key, text);
			});
		};

	}

	return Cyrup;

})));
