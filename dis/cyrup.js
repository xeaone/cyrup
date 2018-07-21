/*
	Name: cyrup
	Version: 0.1.0
	License: MPL-2.0
	Author: Alexander Elias
	Email: alex.steven.elias@gmail.com
	This Source Code Form is subject to the terms of the Mozilla Public
	License, v. 2.0. If a copy of the MPL was not distributed with this
	file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/
var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { step("next", value); }, function (err) { step("throw", err); }); } } return step("next"); }); }; }

(function (global, factory) {
	(typeof exports === 'undefined' ? 'undefined' : _typeof(exports)) === 'object' && typeof module !== 'undefined' ? module.exports = factory() : typeof define === 'function' && define.amd ? define('Cyrup', factory) : global.Cyrup = factory();
})(this, function () {
	'use strict';

	/*
 async hashPassword (password, data) {
 	const self = this;
 		data = data || {};
 	data.rounds = data.rounds || self.ROUNDS;
 	data.encoding = data.encoding || self.ENCODING;
 	data.hashType = data.hashType || self.HASH_TYPE;
 	data.hashBytes = data.hashBytes || self.HASH_BYTES;
 	data.saltBytes = data.saltBytes || self.SALT_BYTES;
 		const salt = await self.randomBytes(data.saltBytes);
 	const hash = await self.pbkdf2(password, salt, data.rounds, data.hashBytes, data.hashType);
 		const buffer = Buffer.alloc(hash.length + salt.length + 8);
 		// include salt length to figure out how much of the hash is salt
 	buffer.writeUInt32BE(salt.length, 0, true);
 	buffer.writeUInt32BE(data.rounds, 4, true);
 		salt.copy(buffer, 8);
 	hash.copy(buffer, salt.length + 8);
 		return buffer.toString(data.encoding);
 },
 	async comparePassword (password, combined, data) {
 	const self = this;
 		data = data || {};
 	data.encoding = data.encoding || self.ENCODING;
 	data.hashType = data.hashType || self.HASH_TYPE;
 		combined = Buffer.from(combined, data.encoding);
 		// extract the salt from the buffer
 	const saltBytes = combined.readUInt32BE(0);
 	const hashBytes = combined.length - saltBytes - 8;
 	const rounds = combined.readUInt32BE(4);
 		const salt = combined.slice(8, saltBytes + 8);
 	const hash = combined.toString('binary', saltBytes + 8);
 		const verify = await self.pbkdf2(password, salt, rounds, hashBytes, data.hashType);
 		return verify.toString('binary') === hash;
 },
 */

	var Cyrup = {

		ENCODING: 'hex',
		ITERATIONS: 99999,

		TAG_BYTES: 16,
		KEY_BYTES: 32,
		SALT_BYTES: 16,
		VECTOR_BYTES: 12,
		SECRET_BYTES: 48,

		HASH: 'sha-512',
		ALGORITHM: 'aes-256-gcm',

		normalizeBytes: function normalizeBytes(algorithm) {
			var self = this;

			if (typeof algorithm === 'number') return algorithm;
			if (algorithm.toLowerCase().indexOf('aes') !== 0) return self.KEY_BYTES;

			var algorithms = algorithm.split('-');
			var bits = parseInt(algorithms[1]);

			return bits === NaN ? self.KEY_BYTES * 8 : bits / 8;
		},
		random: function random(data) {
			var self = this;

			data = data || {};

			return Promise.resolve().then(function () {
				return self.randomBytes(data.bytes);
			}).then(function (buffer) {
				return self.bufferToHex(buffer);
			});
		},
		secret: function secret(data) {
			var self = this;

			data = data || {};
			data.bytes = data.bytes || self.SECRET_BYTES;

			return Promise.resolve().then(function () {
				return self.randomBytes(data.bytes);
			}).then(function (buffer) {
				return self.bufferToHex(buffer);
			});
		},
		hash: function hash(data) {
			var self = this;

			if (!data.item) throw new Error('item required');

			data = data || {};
			data.hash = data.hash || self.HASH;
			data.hash = self.normalizeHash(data.hash);

			return Promise.resolve().then(function () {
				return self.stringToBuffer(data.item);
			}).then(function (buffer) {
				return self.createHash(buffer, data.hash);
			}).then(function (buffer) {
				return self.bufferToHex(buffer);
			});
		},
		encrypt: function encrypt(data) {
			var self = this;

			data = data || {};

			if (!data.item) throw new Error('item required');
			if (!data.password) throw new Error('password required');

			data.hash = data.hash || self.HASH;
			data.algorithm = data.algorithm || self.ALGORITHM;
			data.bytes = data.bytes || data.algorithm;

			data.iterations = data.iterations || self.ITERATIONS;
			data.saltBytes = data.saltBytes || self.SALT_BYTES;
			data.vectorBytes = data.vectorBytes || self.VECTOR_BYTES;

			data.hash = self.normalizeHash(data.hash);
			data.bytes = self.normalizeBytes(data.bytes);
			data.algorithm = self.normalizeAlgorithm(data.algorithm);

			var bSalt = void 0,
			    bText = void 0,
			    bVector = void 0,
			    bPassword = void 0;

			return Promise.all([self.stringToBuffer(data.item), self.randomBytes(data.saltBytes), self.randomBytes(data.vectorBytes), self.stringToBuffer(data.password)]).then(function (results) {
				bText = results[0];
				bSalt = results[1];
				bVector = results[2];
				bPassword = results[3];
			}).then(function () {
				return self.pbkdf2(bPassword, bSalt, data.iterations, data.bytes, data.hash, data.algorithm);
			}).then(function (key) {
				return self.cipher(data.algorithm, key, bVector, bText);
			}).then(function (bEncrypted) {
				return Promise.all([self.bufferToHex(bEncrypted), self.bufferToHex(bVector), self.bufferToHex(bSalt)]).then(function (results) {
					return results.join(':');
				});
			});
		},
		decrypt: function decrypt(data) {
			var self = this;

			data = data || {};

			if (!data.item) throw new Error('item required');
			if (!data.password) throw new Error('password required');

			data.hash = data.hash || self.HASH;
			data.algorithm = data.algorithm || self.ALGORITHM;
			data.bytes = data.bytes || data.algorithm;

			data.iterations = data.iterations || self.ITERATIONS;
			data.saltBytes = data.saltBytes || self.SALT_BYTES;
			data.vectorBytes = data.vectorBytes || self.VECTOR_BYTES;

			data.hash = self.normalizeHash(data.hash);
			data.bytes = self.normalizeBytes(data.bytes);
			data.algorithm = self.normalizeAlgorithm(data.algorithm);

			var items = data.item.split(':');
			var textHex = items[0];
			var vectorHex = items[1];
			var saltHex = items[2];

			var bSalt = void 0,
			    bText = void 0,
			    bVector = void 0,
			    bPassword = void 0;

			return Promise.all([self.hexToBuffer(textHex), self.hexToBuffer(saltHex), self.hexToBuffer(vectorHex), self.stringToBuffer(data.password)]).then(function (results) {
				bText = results[0];
				bSalt = results[1];
				bVector = results[2];
				bPassword = results[3];
			}).then(function () {
				return self.pbkdf2(bPassword, bSalt, data.iterations, data.bytes, data.hash, data.algorithm);
			}).then(function (key) {
				return self.decipher(data.algorithm, key, bVector, bText);
			}).then(function (bDecrypted) {
				return self.bufferToString(bDecrypted);
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

		Cyrup.hexToBuffer = function () {
			var _ref = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee(hex) {
				return regeneratorRuntime.wrap(function _callee$(_context) {
					while (1) {
						switch (_context.prev = _context.next) {
							case 0:
								return _context.abrupt('return', Buffer.from(hex, 'hex'));

							case 1:
							case 'end':
								return _context.stop();
						}
					}
				}, _callee, this);
			}));

			return function (_x) {
				return _ref.apply(this, arguments);
			};
		}();

		Cyrup.bufferToHex = function () {
			var _ref2 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee2(buffer) {
				return regeneratorRuntime.wrap(function _callee2$(_context2) {
					while (1) {
						switch (_context2.prev = _context2.next) {
							case 0:
								return _context2.abrupt('return', buffer.toString('hex'));

							case 1:
							case 'end':
								return _context2.stop();
						}
					}
				}, _callee2, this);
			}));

			return function (_x2) {
				return _ref2.apply(this, arguments);
			};
		}();

		Cyrup.stringToBuffer = function () {
			var _ref3 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee3(string) {
				return regeneratorRuntime.wrap(function _callee3$(_context3) {
					while (1) {
						switch (_context3.prev = _context3.next) {
							case 0:
								return _context3.abrupt('return', Buffer.from(string, 'utf8'));

							case 1:
							case 'end':
								return _context3.stop();
						}
					}
				}, _callee3, this);
			}));

			return function (_x3) {
				return _ref3.apply(this, arguments);
			};
		}();

		Cyrup.bufferToString = function () {
			var _ref4 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee4(buffer) {
				return regeneratorRuntime.wrap(function _callee4$(_context4) {
					while (1) {
						switch (_context4.prev = _context4.next) {
							case 0:
								return _context4.abrupt('return', buffer.toString('utf8'));

							case 1:
							case 'end':
								return _context4.stop();
						}
					}
				}, _callee4, this);
			}));

			return function (_x4) {
				return _ref4.apply(this, arguments);
			};
		}();

		Cyrup.createHash = function () {
			var _ref5 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee5(buffer, type) {
				return regeneratorRuntime.wrap(function _callee5$(_context5) {
					while (1) {
						switch (_context5.prev = _context5.next) {
							case 0:
								return _context5.abrupt('return', Crypto.createHash(type).update(buffer).digest());

							case 1:
							case 'end':
								return _context5.stop();
						}
					}
				}, _callee5, this);
			}));

			return function (_x5, _x6) {
				return _ref5.apply(this, arguments);
			};
		}();

		Cyrup.randomBytes = function () {
			var _ref6 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee6(bytes) {
				return regeneratorRuntime.wrap(function _callee6$(_context6) {
					while (1) {
						switch (_context6.prev = _context6.next) {
							case 0:
								return _context6.abrupt('return', RandomBytes(bytes));

							case 1:
							case 'end':
								return _context6.stop();
						}
					}
				}, _callee6, this);
			}));

			return function (_x7) {
				return _ref6.apply(this, arguments);
			};
		}();

		Cyrup.pbkdf2 = function () {
			var _ref7 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee7(password, salt, iterations, bytes, hash) {
				return regeneratorRuntime.wrap(function _callee7$(_context7) {
					while (1) {
						switch (_context7.prev = _context7.next) {
							case 0:
								return _context7.abrupt('return', Pbkdf2(password, salt, iterations, bytes, hash));

							case 1:
							case 'end':
								return _context7.stop();
						}
					}
				}, _callee7, this);
			}));

			return function (_x8, _x9, _x10, _x11, _x12) {
				return _ref7.apply(this, arguments);
			};
		}();

		Cyrup.cipher = function () {
			var _ref8 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee8(algorithm, key, vector, data) {
				var self, cipher;
				return regeneratorRuntime.wrap(function _callee8$(_context8) {
					while (1) {
						switch (_context8.prev = _context8.next) {
							case 0:
								self = this;
								cipher = Crypto.createCipheriv(algorithm, key, vector);
								return _context8.abrupt('return', Buffer.concat([cipher.update(data, 'utf8'), cipher.final(), cipher.getAuthTag()]));

							case 3:
							case 'end':
								return _context8.stop();
						}
					}
				}, _callee8, this);
			}));

			return function (_x13, _x14, _x15, _x16) {
				return _ref8.apply(this, arguments);
			};
		}();

		Cyrup.decipher = function () {
			var _ref9 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee9(algorithm, key, vector, data) {
				var self, buffer, tag, text, decipher;
				return regeneratorRuntime.wrap(function _callee9$(_context9) {
					while (1) {
						switch (_context9.prev = _context9.next) {
							case 0:
								self = this;
								buffer = Buffer.from(data, 'hex');
								tag = buffer.slice(buffer.byteLength - self.TAG_BYTES);
								text = buffer.slice(0, buffer.byteLength - self.TAG_BYTES);
								decipher = Crypto.createDecipheriv(algorithm, key, vector);


								decipher.setAuthTag(tag);

								return _context9.abrupt('return', Buffer.concat([decipher.update(text), decipher.final()]));

							case 7:
							case 'end':
								return _context9.stop();
						}
					}
				}, _callee9, this);
			}));

			return function (_x17, _x18, _x19, _x20) {
				return _ref9.apply(this, arguments);
			};
		}();
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
			return encrypted.slice(encrypted.byteLength - this.TAG_BYTES);
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

		Cyrup.pbkdf2 = function (password, salt, iterations, bytes, hash, algorithm) {
			var self = this;
			return Promise.resolve().then(function () {
				if (!salt) throw new Error('salt required');
				if (!hash) throw new Error('hash required');
				if (!bytes) throw new Error('bytes required');
				if (!password) throw new Error('password required');
				if (!algorithm) throw new Error('algorithm required');
				if (!iterations) throw new Error('iterations required');
			}).then(function () {
				return window.crypto.subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']);
			}).then(function (key) {
				return window.crypto.subtle.deriveKey({
					salt: salt,
					hash: hash,
					iterations: iterations,
					name: 'PBKDF2'
				}, key, {
					name: algorithm,
					length: bytes * 8,
					tagLength: self.TAG_BYTES * 8
				}, false, ['encrypt', 'decrypt']);
			});
		};

		Cyrup.cipher = function (algorithm, key, vector, data) {
			return Promise.resolve().then(function () {
				return window.crypto.subtle.encrypt({ name: algorithm, iv: vector }, key, data);
			});
		};

		Cyrup.decipher = function (algorithm, key, vector, data) {
			return Promise.resolve().then(function () {
				return window.crypto.subtle.decrypt({ name: algorithm, iv: vector }, key, data);
			});
		};
	}

	return Cyrup;
});