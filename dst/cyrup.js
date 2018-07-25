/*
	Name: cyrup
	Version: 0.2.4
	License: MPL-2.0
	Author: Alexander Elias
	Email: alex.steven.elias@gmail.com
	This Source Code Form is subject to the terms of the Mozilla Public
	License, v. 2.0. If a copy of the MPL was not distributed with this
	file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/
var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

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

function _await(value, then, direct) {
	if (direct) {
		return then ? then(value) : value;
	}value = Promise.resolve(value);return then ? value.then(then) : value;
}(function (global, factory) {
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

		passwordHash: _async(function (password) {
			var _this = this;

			var self = _this;

			if (!password) throw new Error('password required');

			return self.key(password);
		}),
		passwordCompare: _async(function (passwordText, passwordHash) {
			var _this2 = this;

			var self = _this2;

			if (!passwordText) throw new Error('password text required');
			if (!passwordHash) throw new Error('password hash required');

			return _await(self.hexToBuffer(passwordHash.split(':')[1]), function (salt) {
				return _await(self.key(passwordText, { salt: salt }), function (data) {

					return data === passwordHash;
				});
			});
		}),
		random: _async(function (size) {
			var _this3 = this;

			var self = _this3;

			if (!size) throw new Error('size required');

			return _await(self.randomBytes(size), function (buffer) {
				return _await(self.bufferToHex(buffer));
			});
		}),
		secret: _async(function (size) {
			var _this4 = this;

			var self = _this4;

			size = size || self.SECRET;

			return _await(self.randomBytes(size), function (buffer) {
				return _await(self.bufferToHex(buffer));
			});
		}),
		hash: _async(function (item, type) {
			var _this5 = this;

			var self = _this5;

			if (!item) throw new Error('item required');

			type = self.normalizeHash(type || self.HASH);

			return _await(self.stringToBuffer(item), function (buffer) {
				return _await(self.createHash(buffer, type), function (hash) {
					return _await(self.bufferToHex(buffer));
				});
			});
		}),
		key: _async(function (item, data) {
			var _this6 = this;

			var self = _this6;if (!item) throw new Error('item required');

			data = data || {};
			data.size = data.size || self.KEY;
			data.salt = data.salt || self.SALT;
			data.iterations = data.iterations || self.ITERATIONS;data.hash = self.normalizeHash(data.hash || self.HASH);

			return _await(Promise.all([typeof item === 'string' ? self.stringToBuffer(item) : item, typeof data.salt === 'string' ? self.stringToBuffer(data.salt) : typeof data.salt === 'number' ? self.randomBytes(data.salt) : data.salt]), function (_ref) {
				var _ref2 = _slicedToArray(_ref, 2),
				    bItem = _ref2[0],
				    bSalt = _ref2[1];

				return _await(self.pbkdf2(bItem, bSalt, data.iterations, data.size, data.hash), function (bKey) {
					return _await(Promise.all([self.bufferToHex(bKey), self.bufferToHex(bSalt)]), function (_ref3) {
						var _ref4 = _slicedToArray(_ref3, 2),
						    hKey = _ref4[0],
						    hSalt = _ref4[1];

						return hKey + ':' + hSalt;
					});
				});
			});
		}),
		encrypt: _async(function (data, key, algorithm, vector) {
			var _this7 = this;

			var self = _this7;

			if (!key) throw new Error('key required');
			if (!data) throw new Error('data required');

			key = key.split(':');
			vector = vector || self.VECTOR;
			algorithm = self.normalizeAlgorithm(algorithm || self.ALGORITHM);

			return _await(Promise.all([self.hexToBuffer(key[0]), typeof data === 'string' ? self.stringToBuffer(data) : data, typeof vector === 'string' ? self.stringToBuffer(vector) : self.randomBytes(vector)]), function (_ref5) {
				var _ref6 = _slicedToArray(_ref5, 3),
				    bKey = _ref6[0],
				    bData = _ref6[1],
				    bVector = _ref6[2];

				return _await(self.cipher(algorithm, bKey, bVector, bData), function (bEncrypted) {
					return _await(Promise.all([self.bufferToHex(bEncrypted), self.bufferToHex(bVector)]), function (_ref7) {
						var _ref8 = _slicedToArray(_ref7, 2),
						    hEncrypted = _ref8[0],
						    hVector = _ref8[1];

						return hEncrypted + ':' + hVector;
					});
				});
			});
		}),
		decrypt: _async(function (data, key, algorithm) {
			var _this8 = this;

			var self = _this8;

			if (!key) throw new Error('key required');
			if (!data) throw new Error('data required');

			algorithm = self.normalizeAlgorithm(algorithm || self.ALGORITHM);

			key = key.split(':');
			data = data.split(':');

			return _await(Promise.all([self.hexToBuffer(key[0]), self.hexToBuffer(data[0]), self.hexToBuffer(data[1])]), function (_ref9) {
				var _ref10 = _slicedToArray(_ref9, 3),
				    bKey = _ref10[0],
				    bData = _ref10[1],
				    bVector = _ref10[2];

				return _await(self.decipher(algorithm, bKey, bVector, bData), function (bDecrypted) {
					return _await(self.bufferToString(bDecrypted));
				});
			});
		})
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
			var _this9 = this;

			var self = _this9;
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

		Cyrup.hexToBuffer = _async(function (hex) {

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

		Cyrup.bufferToHex = _async(function (buffer) {
			var bytes = new Uint8Array(buffer);
			var hex = new Array(bytes.length);

			for (var i = 0, l = bytes.length; i < l; i++) {
				hex[i] = ('00' + bytes[i].toString(16)).slice(-2);
			}

			return hex.join('');
		});

		Cyrup.stringToBuffer = _async(function (string) {
			var bytes = new Uint8Array(string.length);

			for (var i = 0, l = string.length; i < l; i++) {
				bytes[i] = string.charCodeAt(i);
			}

			return bytes.buffer;
		});

		Cyrup.bufferToString = _async(function (buffer) {
			var bytes = new Uint8Array(buffer);
			var string = new Array(bytes.length);

			for (var i = 0, l = bytes.length; i < l; i++) {
				string[i] = String.fromCharCode(bytes[i]);
			}

			return string.join('');
		});

		Cyrup.createHash = _async(function (buffer, type) {
			return window.crypto.subtle.digest(type, buffer);
		});

		Cyrup.randomBytes = _async(function (size) {
			return window.crypto.getRandomValues(new Uint8Array(size));
		});

		Cyrup.pbkdf2 = _async(function (password, salt, iterations, size, hash) {
			return _await(window.crypto.subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveBits']), function (key) {
				return _await(window.crypto.subtle.deriveBits({
					salt: salt,
					iterations: iterations,
					name: 'PBKDF2',
					hash: { name: hash }
				}, key, size << 3), function (bits) {

					return new Uint8Array(bits);
				});
			});
		});

		Cyrup.cipher = _async(function (algorithm, key, vector, data) {
			var _this10 = this;

			var self = _this10;

			return _await(window.crypto.subtle.importKey('raw', key, {
				name: algorithm
			}, false, ['encrypt']), function (oKey) {
				return _await(window.crypto.subtle.encrypt({
					iv: vector,
					name: algorithm,
					tagLength: self.TAG * 8
				}, oKey, data));
			});
		});

		Cyrup.decipher = _async(function (algorithm, key, vector, data) {
			var _this11 = this;

			var self = _this11;

			return _await(window.crypto.subtle.importKey('raw', key, {
				name: algorithm
			}, false, ['decrypt']), function (oKey) {
				return _await(window.crypto.subtle.decrypt({
					iv: vector,
					name: algorithm,
					tagLength: self.TAG * 8
				}, oKey, data));
			});
		});
	}

	return Cyrup;
});