
const Cyrup = {

	ENCODING: 'hex',
	ITERATIONS: 99999,

	LENGTH: 32,
	// KEY_LENGTH: 32,
	SALT_LENGTH: 16,
	VECTOR_LENGTH: 12,
	SECRET_LENGTH: 48,

	TAG_BITS: 128,
	TAG_BYTES: 16,

	HASH: 'sha-512',
	ALGORITHM: 'aes-256-gcm',

	normalizeLength (algorithm, length) {
		if (typeof algorithm === 'number') return algorithm;
		if (algorithm.toLowerCase().indexOf('aes') !== 0) return length;
		const algorithms = algorithm.split('-');
		// TODO might need to get bytes in stead of bits for Node
		const bits = parseInt(algorithms[1]);
		return bits === NaN ? length : bits;
	},

	secret (data) {
		const self = this;

		data = data || {};
		data.size = data.size || self.SECRET_LENGTH;

		return Promise.resolve().then(function () {
			return self.randomBytes(data.size);
		}).then(function (buffer) {
			return self.bufferToHex(buffer);
		});
	},

	hash (data) {
		const self = this;

		data = data || {};
		data.type = data.type || self.HASH;

		return Promise.resolve().then(function () {
			return self.stringToBuffer(data.text);
		}).then(function (buffer) {
			return self.createHash(buffer, data.type);
		}).then(function (buffer) {
			return self.bufferToHex(buffer);
		});
	},

	// key () {
	// },

	encrypt (password, text, data) {
		const self = this;

		if (!text) throw new Error('text required');
		if (!password) throw new Error('password required');

		data = data || {};

		data.hash = data.hash || self.HASH;
		data.algorithm = data.algorithm || self.ALGORITHM;
		data.length = data.length || data.algorithm;

		data.iterations = data.iterations || self.ITERATIONS;
		data.saltLength = data.saltLength || self.SALT_LENGTH;
		data.vectorLength = data.vectorLength || self.VECTOR_LENGTH;

		data.hash = self.normalizeHash(data.hash);
		data.algorithm = self.normalizeAlgorithm(data.algorithm);
		data.length = self.normalizeLength(data.length, self.LENGTH);

		let bSalt, bText, bVector, bPassword;

		return Promise.all([
			self.stringToBuffer(text),
			self.stringToBuffer(password),
			self.randomBytes(data.saltLength),
			self.randomBytes(data.vectorLength)
		]).then(function (items) {
			bText = items[0];
			bPassword = items[1];
			bSalt = items[2];
			bVector = items[3];
		}).then(function () {
			return self.pbkdf2(bPassword, bSalt, data.iterations, data.length, data.hash, data.algorithm);
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

		const encrypteds = encrypted.split(':');
		const textHex = encrypteds[0];
		const vectorHex = encrypteds[1];
		const saltHex = encrypteds[2];

		data = data || {};

		data.hash = data.hash || self.HASH;
		data.algorithm = data.algorithm || self.ALGORITHM;
		data.length = data.length || data.algorithm;

		data.iterations = data.iterations || self.ITERATIONS;
		data.saltLength = data.saltLength || self.SALT_LENGTH;
		data.vectorLength = data.vectorLength || self.VECTOR_LENGTH;

		data.hash = self.normalizeHash(data.hash);
		data.algorithm = self.normalizeAlgorithm(data.algorithm);
		data.length = self.normalizeLength(data.length, self.LENGTH);

		let bSalt, bText, bVector, bPassword;

		return Promise.all([
			self.hexToBuffer(textHex),
			self.hexToBuffer(saltHex),
			self.hexToBuffer(vectorHex),
			self.stringToBuffer(password)
		]).then(function (items) {
			bText = items[0];
			bSalt = items[1];
			bVector = items[2];
			bPassword = items[3];
		}).then(function () {
			return self.pbkdf2(bPassword, bSalt, data.iterations, data.length, data.hash, data.algorithm);
		}).then(function (key) {
			return self._decrypt(data.algorithm, key, bVector, bText);
		}).then(function (bDecrypted) {
			return self.bufferToString(bDecrypted);
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
		if (algorithm.indexOf('aes') !== 0) return algorithm;
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

	Cyrup.randomBytes = async function () {
		return RandomBytes.apply(null, arguments);
	};

	Cyrup.pbkdf2 = async function (password, salt, iterations, length, hash) {
		length = length/8; // convert bites to bytes
		return Pbkdf2(password, salt, iterations, length, hash);
	};

	Cyrup._encrypt = async function (algorithm, key, vector, data) {
		const self = this;
		const cipher = Crypto.createCipheriv(algorithm, key, vector);
		return Buffer.concat([cipher.update(data, 'utf8'), cipher.final(), cipher.getAuthTag()]);
	};

	Cyrup._decrypt = async function (algorithm, key, vector, data) {
		const self = this;
		const buffer = Buffer.from(data, 'hex');
		const tag = buffer.slice(buffer.byteLength - self.TAG_BYTES);
		const text = buffer.slice(0, buffer.byteLength - self.TAG_BYTES);
		const decipher = Crypto.createDecipheriv(algorithm, key, vector);

		decipher.setAuthTag(tag);

		return Buffer.concat([decipher.update(text), decipher.final()]);
	};

} else {

	Cyrup.normalizeHash = function (hash) {
		return hash.toUpperCase();
	};

	Cyrup.normalizeAlgorithm = function (algorithm) {
		if (algorithm.indexOf('aes') !== 0) return algorithm;
		const algorithms = algorithm.split('-');
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

			if ((hex.length % 2) !== 0) {
				throw new RangeError('Expected string to be an even number of characters');
			}

			let bytes = new Uint8Array(hex.length / 2);

			for (let i = 0, l = hex.length; i < l; i += 2) {
				bytes[i/2] = parseInt(hex.substring(i, i + 2), 16);
			}

			return bytes.buffer
		});
	};

	Cyrup.bufferToHex = function (buffer) {
		return Promise.resolve().then(function () {
			let bytes = new Uint8Array(buffer);
		 	const hexes = [];

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
			const bytes = new Uint8Array(string.length);

			for (let i = 0, l = string.length; i < l; i++) {
				bytes[i] = string.charCodeAt(i);
			}

			return bytes.buffer
		});
	};

    Cyrup.bufferToString = function (buffer) {
		return Promise.resolve().then(function () {
	        let data = '';
			const bytes = new Uint8Array(buffer);

	        for (let i = 0, l = bytes.length; i < l; i++) {
				data += String.fromCharCode(bytes[i]);
	        }

	        return data;
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

	Cyrup.pbkdf2 = function (password, salt, iterations, length, hash, algorithm) {
		const self = this;
		return Promise.resolve().then(function () {
			if (!salt) throw new Error('salt required');
			if (!hash) throw new Error('hash required');
			if (!length) throw new Error('length required');
			if (!password) throw new Error('password required');
			if (!algorithm) throw new Error('algorithm required');
			if (!iterations) throw new Error('iterations required');
		}).then(function () {
			return window.crypto.subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']);
		}).then(function (key) {
			return window.crypto.subtle.deriveKey({
				salt,
				hash,
				iterations,
				name: 'PBKDF2'
			}, key, {
				name: algorithm,
				length: length * 8,
				tagLength: self.TAG_BITS
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

export default Cyrup;
