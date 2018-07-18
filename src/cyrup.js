
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

	Cyrup.createHash = function (buffer, type) {
		return Promise.resolve().then(function () {
			return Crypto.createHash(type).update(buffer).digest();
		});
	};

	Cyrup.pbkdf2 = Util.promisify(Crypto.pbkdf2);

} else {

	Cyrup.HASH_TYPE = 'SHA-512';
	Cyrup.ALGORITHM = 'AES-GCM';

	Ppolly.hexToBuffer (hex) {
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

	Cyrup.bufferToHex (buffer) {
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

	Cyrup.stringToBuffer (string) {
		return Promise.resolve().then(function () {
			let bytes = new Uint8Array(string.length);

			for (let i = 0, l = string.length; i < l; i++) {
				bytes[i] = string.charCodeAt(i);
			}

			return bytes.buffer
		});
	};

    Cyrup.bufferToString (buffer) {
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

		if (!salt) throw new Error('salt required');
		if (!length) throw new Error('length required');
		if (!digest) throw new Error('digest required');
		if (!password) throw new Error('password required');
		if (!iterations) throw new Error('iterations required');

		return Promise.resolve().then(function () {
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

}

export default Cyrup;
