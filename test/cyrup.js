(function (global, factory) {
	typeof exports === 'object' && typeof module !== 'undefined' ? module.exports = factory() :
	typeof define === 'function' && define.amd ? define('Cyrup', factory) :
	(global.Cyrup = factory());
}(this, (function () { 'use strict';

	const Cyrup = {

		ENCODING: 'hex',
		ITERATIONS: 999999,


		KEY: 32,
		TAG: 16,
		SALT: 16,
		VECTOR: 12,
		SECRET: 48,
		HASH: 'sha-512',
		ALGORITHM: 'aes-256-gcm',

		passwordHash (password) {
			const self = this;

			if (!password) throw new Error('password item required');

			return Promise.resolve().then(function () {
				return self.key({ item: password });
			});
		},

		passwordCompare (password, key) {
			const self = this;

			if (!key) throw new Error('key required');
			if (!password) throw new Error('password required');

			const parts = key.split(':');

			return Promise.resolve().then(function () {
				return self.hexToBuffer(parts[1])
			}).then(function (salt) {
				return self.key({ item: password, salt });
			}).then(function (data) {
				return data === key;
			});
		},

		random (size) {
			const self = this;

			if (!size) throw new Error('size required');

			return Promise.resolve().then(function () {
				return self.randomBytes(size);
			}).then(function (buffer) {
				return self.bufferToHex(buffer);
			});
		},

		secret (size) {
			const self = this;

			size = size || self.SECRET;

			return Promise.resolve().then(function () {
				return self.randomBytes(size);
			}).then(function (buffer) {
				return self.bufferToHex(buffer);
			});
		},

		hash (item, type) {
			const self = this;

			if (!item) throw new Error('item required');

			type = self.normalizeHash(type || self.HASH);

			return Promise.resolve().then(function () {
				return self.stringToBuffer(item);
			}).then(function (buffer) {
				return self.createHash(buffer, type);
			}).then(function (buffer) {
				return self.bufferToHex(buffer);
			});
		},

		key (data) {
			const self = this;

			data = data || {};

			if (!data.item) throw new Error('item required');

			data.size = data.size || self.KEY;
			data.salt = data.salt || self.SALT;
			data.iterations = data.iterations || self.ITERATIONS;
			data.hash = self.normalizeHash(data.hash || self.HASH);

			let salt, item;

			return Promise.all([
				typeof data.item === 'string' ? self.stringToBuffer(data.item) : data.item,
				typeof data.salt === 'string' ?
					self.stringToBuffer(data.salt) :
					typeof data.salt === 'number' ?
						self.randomBytes(data.salt) :
						data.salt
			]).then(function (results) {
				item = results[0];
				salt = results[1];
				return self.pbkdf2(item, salt, data.iterations, data.size, data.hash);
			}).then(function (key) {
				return Promise.all([
					self.bufferToHex(key),
					self.bufferToHex(salt)
				]).then(function (results) {
					return results.join(':');
				});
			});
		},

		encrypt (data) {
			const self = this;

			data = data || {};

			if (!data.key) throw new Error('key required');
			if (!data.item) throw new Error('item required');

			data.vector = data.vector || self.VECTOR;
			data.algorithm = self.normalizeAlgorithm(data.algorithm || self.ALGORITHM);

			let vector, item;
			let key = data.key.split(':')[0];

			return Promise.all([
				self.hexToBuffer(key),
				typeof data.item === 'string' ? self.stringToBuffer(data.item) : data.item,
				typeof data.vector === 'string' ? self.stringToBuffer(data.vector) : self.randomBytes(data.vector)
			]).then(function (results) {
				key = results[0];
				item = results[1];
				vector = results[2];
				return self.cipher(data.algorithm, key, vector, item);
			}).then(function (encrypted) {
				return Promise.all([
					self.bufferToHex(encrypted),
					self.bufferToHex(vector)
				]).then(function (results) {
					return results.join(':');
				});
			});
		},

		decrypt (data) {
			const self = this;

			data = data || {};

			if (!data.key) throw new Error('key required');
			if (!data.item) throw new Error('item required');

			data.algorithm = self.normalizeAlgorithm(data.algorithm || self.ALGORITHM);

			const items = data.item.split(':');
			let key = data.key.split(':')[0];
			let item = items[0];
			let vector = items[1];

			return Promise.all([
				self.hexToBuffer(key),
				self.hexToBuffer(item),
				self.hexToBuffer(vector)
			]).then(function (results) {
				key = results[0];
				item = results[1];
				vector = results[2];
				return self.decipher(data.algorithm, key, vector, item);
			}).then(function (decrypted) {
				return self.bufferToString(decrypted);
			});
		}

	};

	if (typeof window === 'undefined') {

		const Util = require('util');
		const Crypto = require('crypto');
		const Pbkdf2 = Util.promisify(Crypto.pbkdf2);
		const RandomBytes = Util.promisify(Crypto.randomBytes);

		Cyrup.normalizeHash = function (hash) {
			return hash.replace('-', '').toLowerCase();
		};

		Cyrup.normalizeAlgorithm = function (algorithm) {
			if (algorithm.toLowerCase().indexOf('aes') !== 0) return algorithm;
			return algorithm.toLowerCase();
		};

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

		Cyrup.createHash = async function (buffer, type) {
			return Crypto.createHash(type).update(buffer).digest();
		};

		Cyrup.randomBytes = async function (bytes) {
			return RandomBytes(bytes);
		};

		Cyrup.pbkdf2 = async function (password, salt, iterations, size, hash) {
			return Pbkdf2(password, salt, iterations, size, hash);
		};

		Cyrup.cipher = async function (algorithm, key, vector, data) {
			const self = this;
			const cipher = Crypto.createCipheriv(algorithm, key, vector);
			return Buffer.concat([cipher.update(data, 'utf8'), cipher.final(), cipher.getAuthTag()]);
		};

		Cyrup.decipher = async function (algorithm, key, vector, data) {
			const self = this;
			const buffer = Buffer.from(data, 'hex');
			const tag = buffer.slice(buffer.byteLength - self.TAG);
			const text = buffer.slice(0, buffer.byteLength - self.TAG);
			const decipher = Crypto.createDecipheriv(algorithm, key, vector);

			decipher.setAuthTag(tag);

			return Buffer.concat([decipher.update(text), decipher.final()]);
		};

	} else {

		Cyrup.normalizeHash = function (hash) {
			return hash.toUpperCase();
		};

		Cyrup.normalizeAlgorithm = function (algorithm) {
			if (algorithm.toLowerCase().indexOf('aes') !== 0) return algorithm;
			const algorithms = algorithm.split('-');
			return (algorithms[0] + '-' + algorithms[2]).toUpperCase();
		};

		Cyrup.getAuthTag = function (encrypted) {
			return encrypted.slice(encrypted.byteLength - this.TAG);
		};

		Cyrup.hexToBuffer = function (hex) {
			return Promise.resolve().then(function () {

				if (typeof hex !== 'string') {
					throw new TypeError('Expected input to be a string');
				}

				if ((hex.length % 2) !== 0) {
					throw new RangeError('Expected string to be an even number of characters');
				}

				const bytes = new Uint8Array(hex.length / 2);

				for (let i = 0, l = hex.length; i < l; i += 2) {
					bytes[i/2] = parseInt( hex.substring(i, i + 2), 16 );
				}

				return bytes.buffer
			});
		};

		Cyrup.bufferToHex = function (buffer) {
			return Promise.resolve().then(function () {
				const bytes = new Uint8Array(buffer);
			 	const hex = new Array(bytes.length);

				for (let i = 0, l = bytes.length; i < l; i++) {
					hex[i] = ( '00' + bytes[i].toString(16) ).slice(-2);
				}

				return hex.join('');
			});
		};

		Cyrup.stringToBuffer = function (string) {
			return Promise.resolve().then(function () {
				const bytes = new Uint8Array(string.length);

				for (let i = 0, l = string.length; i < l; i++) {
					bytes[i] = string.charCodeAt(i);
				}

				return bytes.buffer
			});
		};

	    Cyrup.bufferToString = function (buffer) {
			return Promise.resolve().then(function () {
				const bytes = new Uint8Array(buffer);
				const string = new Array(bytes.length);

		        for (let i = 0, l = bytes.length; i < l; i++) {
					string[i] = String.fromCharCode(bytes[i]);
		        }

		        return string.join('');
			});
	    };

		Cyrup.createHash = function (buffer, type) {
			return Promise.resolve().then(function () {
				return window.crypto.subtle.digest(type, buffer);
			});
		};

		Cyrup.randomBytes = function (size) {
			return Promise.resolve().then(function () {
				return window.crypto.getRandomValues(new Uint8Array(size));
			});
		};

		Cyrup.pbkdf2 = function (password, salt, iterations, size, hash) {
			return Promise.resolve().then(function () {
				return window.crypto.subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveBits']);
			}).then(function (key) {
				return window.crypto.subtle.deriveBits({
					salt,
					iterations,
					name: 'PBKDF2',
					hash: { name: hash }
				}, key, size << 3);
			}).then(function (bits) {
				return new Uint8Array(bits);
			});
		};

		Cyrup.cipher = function (algorithm, key, vector, item) {
			const self = this;
			return Promise.resolve().then(function () {
				return window.crypto.subtle.importKey('raw', key, { name: algorithm }, false, ['encrypt']);
			}).then(function (data) {
				const tagLength = self.TAG * 8;
				return window.crypto.subtle.encrypt({ name: algorithm, iv: vector, tagLength }, data, item);
			});
		};

		Cyrup.decipher = function (algorithm, key, vector, item) {
			const self = this;
			return Promise.resolve().then(function () {
				return window.crypto.subtle.importKey('raw', key, { name: algorithm }, false, ['decrypt']);
			}).then(function (data) {
				const tagLength = self.TAG * 8;
				return window.crypto.subtle.decrypt({ name: algorithm, iv: vector, tagLength }, data, item);
			});
		};

	}

	return Cyrup;

})));
