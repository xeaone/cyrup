/*
	Name: cyrup
	Version: 0.2.0
	License: MPL-2.0
	Author: Alexander Elias
	Email: alex.steven.elias@gmail.com
	This Source Code Form is subject to the terms of the Mozilla Public
	License, v. 2.0. If a copy of the MPL was not distributed with this
	file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/
var _async = function () {
	try {
		if (isNaN.apply(null, {})) {
			return function (f) {
				return function () {
					try {
						return Promise.resolve(f.apply(this, arguments));
					} catch (e) {
						return Promise.reject(e);
					}
				};
			};
		}
	} catch (e) {}return function (f) {
		// Pre-ES5.1 JavaScript runtimes don't accept array-likes in Function.apply
		return function () {
			var args = [];for (var i = 0; i < arguments.length; i++) {
				args[i] = arguments[i];
			}try {
				return Promise.resolve(f.apply(this, args));
			} catch (e) {
				return Promise.reject(e);
			}
		};
	};
}(),
    _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

(function (global, factory) {
	(typeof exports === 'undefined' ? 'undefined' : _typeof(exports)) === 'object' && typeof module !== 'undefined' ? module.exports = factory() : typeof define === 'function' && define.amd ? define('Cyrup', factory) : global.Cyrup = factory();
})(this, function () {
	'use strict';

	var Cyrup = {

		ENCODING: 'hex',
		ITERATIONS: 999999,

		KEY: 32,
		TAG: 16,
		SALT: 16,
		VECTOR: 12,
		SECRET: 48,
		HASH: 'sha-512',
		ALGORITHM: 'aes-256-gcm',

		passwordHash: function passwordHash(password) {
			var self = this;

			if (!password) throw new Error('password item required');

			return Promise.resolve().then(function () {
				return self.key(password);
			});
		},
		passwordCompare: function passwordCompare(passwordText, passwordHash) {
			var self = this;

			if (!passwordText) throw new Error('password text required');
			if (!passwordHash) throw new Error('password hash required');

			return Promise.resolve().then(function () {
				return self.hexToBuffer(passwordHash.split(':')[1]);
			}).then(function (salt) {
				return self.key(passwordText, { salt: salt });
			}).then(function (data) {
				return data === passwordHash;
			});
		},
		random: function random(size) {
			var self = this;

			if (!size) throw new Error('size required');

			return Promise.resolve().then(function () {
				return self.randomBytes(size);
			}).then(function (buffer) {
				return self.bufferToHex(buffer);
			});
		},
		secret: function secret(size) {
			var self = this;

			size = size || self.SECRET;

			return Promise.resolve().then(function () {
				return self.randomBytes(size);
			}).then(function (buffer) {
				return self.bufferToHex(buffer);
			});
		},
		hash: function hash(item, type) {
			var self = this;

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
		key: function key(item, data) {
			var self = this;

			if (!item) throw new Error('item required');

			data = data || {};
			data.size = data.size || self.KEY;
			data.salt = data.salt || self.SALT;
			data.iterations = data.iterations || self.ITERATIONS;
			data.hash = self.normalizeHash(data.hash || self.HASH);

			var salt = void 0;

			return Promise.all([typeof item === 'string' ? self.stringToBuffer(item) : item, typeof data.salt === 'string' ? self.stringToBuffer(data.salt) : typeof data.salt === 'number' ? self.randomBytes(data.salt) : data.salt]).then(function (results) {
				item = results[0];
				salt = results[1];
				return self.pbkdf2(item, salt, data.iterations, data.size, data.hash);
			}).then(function (key) {
				return Promise.all([self.bufferToHex(key), self.bufferToHex(salt)]).then(function (results) {
					return results.join(':');
				});
			});
		},
		encrypt: function encrypt(item, key, algorithm, vector) {
			var self = this;

			if (!key) throw new Error('key required');
			if (!item) throw new Error('item required');

			vector = vector || self.VECTOR;
			algorithm = self.normalizeAlgorithm(algorithm || self.ALGORITHM);

			key = key.split(':')[0];

			return Promise.all([self.hexToBuffer(key), typeof item === 'string' ? self.stringToBuffer(item) : item, typeof vector === 'string' ? self.stringToBuffer(vector) : self.randomBytes(vector)]).then(function (results) {
				key = results[0];
				item = results[1];
				vector = results[2];
				return self.cipher(algorithm, key, vector, item);
			}).then(function (encrypted) {
				return Promise.all([self.bufferToHex(encrypted), self.bufferToHex(vector)]).then(function (results) {
					return results.join(':');
				});
			});
		},
		decrypt: function decrypt(item, key, algorithm) {
			var self = this;

			if (!key) throw new Error('key required');
			if (!item) throw new Error('item required');

			algorithm = self.normalizeAlgorithm(algorithm || self.ALGORITHM);

			var vector = void 0;
			var items = item.split(':');

			key = key.split(':')[0];
			item = items[0];
			vector = items[1];

			return Promise.all([self.hexToBuffer(key), self.hexToBuffer(item), self.hexToBuffer(vector)]).then(function (results) {
				key = results[0];
				item = results[1];
				vector = results[2];
				return self.decipher(algorithm, key, vector, item);
			}).then(function (decrypted) {
				return self.bufferToString(decrypted);
			});
		}
	};

	if (typeof window === 'undefined') {

		var Util = require('util');
		var Crypto = require('crypto');
		var Pbkdf2 = Util.promisify(Crypto.pbkdf2);
		var RandomBytes = Util.promisify(Crypto.randomBytes);

		Cyrup.normalizeHash = function (hash) {
			return hash.replace('-', '').toLowerCase();
		};

		Cyrup.normalizeAlgorithm = function (algorithm) {
			if (algorithm.toLowerCase().indexOf('aes') !== 0) return algorithm;
			return algorithm.toLowerCase();
		};

		Cyrup.hexToBuffer = _async(function (hex) {
			return Buffer.from(hex, 'hex');
		});

		Cyrup.bufferToHex = _async(function (buffer) {
			return buffer.toString('hex');
		});

		Cyrup.stringToBuffer = _async(function (string) {
			return Buffer.from(string, 'utf8');
		});

		Cyrup.bufferToString = _async(function (buffer) {
			return buffer.toString('utf8');
		});

		Cyrup.createHash = _async(function (buffer, type) {
			return Crypto.createHash(type).update(buffer).digest();
		});

		Cyrup.randomBytes = _async(function (bytes) {
			return RandomBytes(bytes);
		});

		Cyrup.pbkdf2 = _async(function (password, salt, iterations, size, hash) {
			return Pbkdf2(password, salt, iterations, size, hash);
		});

		Cyrup.cipher = _async(function (algorithm, key, vector, data) {
			var cipher = Crypto.createCipheriv(algorithm, key, vector);
			return Buffer.concat([cipher.update(data, 'utf8'), cipher.final(), cipher.getAuthTag()]);
		});

		Cyrup.decipher = _async(function (algorithm, key, vector, data) {
			var _this = this;

			var self = _this;
			var buffer = Buffer.from(data, 'hex');
			var tag = buffer.slice(buffer.byteLength - self.TAG);
			var text = buffer.slice(0, buffer.byteLength - self.TAG);
			var decipher = Crypto.createDecipheriv(algorithm, key, vector);

			decipher.setAuthTag(tag);

			return Buffer.concat([decipher.update(text), decipher.final()]);
		});
	} else {

		Cyrup.normalizeHash = function (hash) {
			return hash.toUpperCase();
		};

		Cyrup.normalizeAlgorithm = function (algorithm) {
			if (algorithm.toLowerCase().indexOf('aes') !== 0) return algorithm;
			var algorithms = algorithm.split('-');
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

				if (hex.length % 2 !== 0) {
					throw new RangeError('Expected string to be an even number of characters');
				}

				var bytes = new Uint8Array(hex.length / 2);

				for (var i = 0, l = hex.length; i < l; i += 2) {
					bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
				}

				return bytes.buffer;
			});
		};

		Cyrup.bufferToHex = function (buffer) {
			return Promise.resolve().then(function () {
				var bytes = new Uint8Array(buffer);
				var hex = new Array(bytes.length);

				for (var i = 0, l = bytes.length; i < l; i++) {
					hex[i] = ('00' + bytes[i].toString(16)).slice(-2);
				}

				return hex.join('');
			});
		};

		Cyrup.stringToBuffer = function (string) {
			return Promise.resolve().then(function () {
				var bytes = new Uint8Array(string.length);

				for (var i = 0, l = string.length; i < l; i++) {
					bytes[i] = string.charCodeAt(i);
				}

				return bytes.buffer;
			});
		};

		Cyrup.bufferToString = function (buffer) {
			return Promise.resolve().then(function () {
				var bytes = new Uint8Array(buffer);
				var string = new Array(bytes.length);

				for (var i = 0, l = bytes.length; i < l; i++) {
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
					salt: salt,
					iterations: iterations,
					name: 'PBKDF2',
					hash: { name: hash }
				}, key, size << 3);
			}).then(function (bits) {
				return new Uint8Array(bits);
			});
		};

		Cyrup.cipher = function (algorithm, key, vector, item) {
			var self = this;
			return Promise.resolve().then(function () {
				return window.crypto.subtle.importKey('raw', key, { name: algorithm }, false, ['encrypt']);
			}).then(function (data) {
				var tagLength = self.TAG * 8;
				return window.crypto.subtle.encrypt({ name: algorithm, iv: vector, tagLength: tagLength }, data, item);
			});
		};

		Cyrup.decipher = function (algorithm, key, vector, item) {
			var self = this;
			return Promise.resolve().then(function () {
				return window.crypto.subtle.importKey('raw', key, { name: algorithm }, false, ['decrypt']);
			}).then(function (data) {
				var tagLength = self.TAG * 8;
				return window.crypto.subtle.decrypt({ name: algorithm, iv: vector, tagLength: tagLength }, data, item);
			});
		};
	}

	return Cyrup;
});