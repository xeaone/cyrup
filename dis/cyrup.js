/*
	Name: cyrup
	Version: 0.0.6
	License: MPL-2.0
	Author: Alexander Elias
	Email: alex.steven.elias@gmail.com
	This Source Code Form is subject to the terms of the Mozilla Public
	License, v. 2.0. If a copy of the MPL was not distributed with this
	file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/
var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

(function (global, factory) {
	(typeof exports === 'undefined' ? 'undefined' : _typeof(exports)) === 'object' && typeof module !== 'undefined' ? module.exports = factory() : typeof define === 'function' && define.amd ? define('Cyrup', factory) : global.Cyrup = factory();
})(this, function () {
	'use strict';

	var browser = {

		ROUNDS: 99999,
		ENCODING: 'hex',
		ALGORITHM: 'AES-GCM',

		SALT_BYTES: 16,
		HASH_BYTES: 32,
		VECTOR_BYTES: 12,
		SECRET_BYTES: 48,

		HASH_TYPE: 'SHA-512',

		randomBytes: function randomBytes(bytes) {
			return Promise.resolve().then(function () {
				return window.crypto.getRandomValues(new Uint8Array(bytes));
			});
		},
		hexToBuffer: function hexToBuffer(hex) {
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
		},
		bufferToHex: function bufferToHex(buffer) {
			return Promise.resolve().then(function () {
				var bytes = new Uint8Array(buffer);
				var hexes = [];

				for (var i = 0, l = bytes.length; i < l; i++) {

					var hex = bytes[i].toString(16);
					var pad = ('00' + hex).slice(-2);

					hexes.push(pad);
				}

				return hexes.join('');
			});
		},
		stringToBuffer: function stringToBuffer(string) {
			return Promise.resolve().then(function () {
				var bytes = new Uint8Array(string.length);

				for (var i = 0, l = string.length; i < l; i++) {
					bytes[i] = string.charCodeAt(i);
				}

				return bytes.buffer;
			});
		},
		bufferToString: function bufferToString(buffer) {
			return Promise.resolve().then(function () {
				var data = '';
				var bytes = new Uint8Array(buffer);

				for (var i = 0, l = bytes.length; i < l; i++) {
					data += String.fromCharCode(bytes[i]);
				}

				return data;
			});
		},
		pbkdf2: function pbkdf2(password, salt, iterations, digest, algorithm) {
			var self = this;

			if (!salt) throw new Error('salt required');
			if (!digest) throw new Error('digest required');
			if (!password) throw new Error('password required');
			if (!iterations) throw new Error('iterations required');

			return Promise.resolve().then(function () {
				return window.crypto.subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']);
			}).then(function (key) {
				return window.crypto.subtle.deriveKey({
					salt: salt,
					name: 'PBKDF2',
					hash: digest || self.HASH_TYPE,
					iterations: iterations || self.ROUNDS
				}, key, {
					length: 256,
					name: algorithm || self.ALGORITHM
				}, false, ['encrypt', 'decrypt']);
			});
		},
		secret: function secret(data) {
			var self = this;

			data = data || {};
			data.bytes = data.bytes || self.SECRET_BYTES;
			data.encoding = data.encoding || self.ENCODING;

			return Promise.resolve().then(function () {
				return self.randomBytes(data.bytes);
			}).then(function (buffer) {
				return self.bufferToHex(buffer);
			});
		},
		hash: function hash(text, data) {
			var self = this;

			data = data || {};
			data.hashType = data.hashType || self.HASH_TYPE;

			return Promise.resolve().then(function () {
				return self.stringToBuffer(text);
			}).then(function (textBuffer) {
				return window.crypto.subtle.digest(data.hashType, textBuffer);
			}).then(function (hashBuffer) {
				return self.bufferToHex(hashBuffer);
			});
		},
		encrypt: function encrypt(password, text, data) {

			if (!text) throw new Error('text required');
			if (!password) throw new Error('password required');

			var self = this;

			var salt = void 0,
			    vector = void 0,
			    passwordBuffer = void 0;

			data = data || {};
			data.rounds = data.rounds || self.ROUNDS;
			data.encoding = data.encoding || self.ENCODING;
			data.hashType = data.hashType || self.HASH_TYPE;
			data.algorithm = data.algorithm || self.ALGORITHM;
			data.hashBytes = data.hashBytes || self.HASH_BYTES;
			data.saltBytes = data.saltBytes || self.SALT_BYTES;
			data.vectorBytes = data.vectorBytes || self.VECTOR_BYTES;

			return Promise.resolve().then(function () {
				return Promise.all([self.stringToBuffer(password), self.randomBytes(self.SALT_BYTES), self.randomBytes(self.VECTOR_BYTES)]);
			}).then(function (items) {
				salt = items[1];
				vector = items[2];
				passwordBuffer = items[0];
			}).then(function () {
				return Promise.all([self.stringToBuffer(text), self.pbkdf2(passwordBuffer, salt, data.rounds, data.hashType, data.algorithm)]);
			}).then(function (items) {
				var textBuffer = items[0];
				var key = items[1];
				return window.crypto.subtle.encrypt({
					name: self.ALGORITHM,
					iv: vector
				}, key, textBuffer);
			}).then(function (encrypted) {
				return Promise.all([self.bufferToHex(encrypted), self.bufferToHex(vector), self.bufferToHex(salt)]).then(function (results) {
					return results.join(':');
				});
			});
		},
		decrypt: function decrypt(password, encrypted, data) {

			if (!password) throw new Error('password required');
			if (!encrypted) throw new Error('encrypted required');

			var self = this;
			var encrypteds = encrypted.split(':');
			var textHex = encrypteds[0];
			var vectorHex = encrypteds[1];
			var saltHex = encrypteds[2];

			var passwordBuffer = void 0,
			    textBuffer = void 0,
			    vectorBuffer = void 0,
			    saltBuffer = void 0;

			data = data || {};
			data.rounds = data.rounds || self.ROUNDS;
			data.encoding = data.encoding || self.ENCODING;
			data.hashType = data.hashType || self.HASH_TYPE;
			data.algorithm = data.algorithm || self.ALGORITHM;
			data.hashBytes = data.hashBytes || self.HASH_BYTES;

			return Promise.all([self.hexToBuffer(textHex), self.hexToBuffer(vectorHex), self.hexToBuffer(saltHex), self.stringToBuffer(password)]).then(function (items) {
				textBuffer = items[0];
				vectorBuffer = items[1];
				saltBuffer = items[2];
				passwordBuffer = items[3];
			}).then(function () {
				return self.pbkdf2(passwordBuffer, saltBuffer, data.rounds, data.hashType, data.algorithm);
			}).then(function (key) {
				return window.crypto.subtle.decrypt({
					name: self.ALGORITHM,
					iv: vectorBuffer
				}, key, textBuffer);
			}).then(function (decrypted) {
				return self.bufferToString(decrypted);
			});
		}
	};

	return browser;
});