
const Cyrup = {

	ENCODING: 'hex',
	ITERATIONS: 99999,

	LENGTH: 32,
	// KEY_LENGTH: 32,
	SALT_LENGTH: 16,
	VECTOR_LENGTH: 12,
	SECRET_LENGTH: 48,

	HASH: 'sha-512',
	ALGORITHM: 'aes-256-gcm',

	getTag (encrypted, length) {
		const self = this;
		length = length || 128;
	    return encrypted.slice(encrypted.byteLength - ((length + 7) >> 3))
	},

	normalizeLength (algorithm, length) {
		const self = this;
		if (algorithm.indexOf('aes') !== 0) return length;
		const algorithms = algorithm.split('-');
		const data = parseInt(algorithms[1]) / 8; // aes length / 8
		return data === NaN ? length : data;
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

	encrypt (password, text, data) {
		const self = this;

		if (!text) throw new Error('text required');
		if (!password) throw new Error('password required');

		data = data || {};

		data.hash = data.hash || self.HASH;
		data.algorithm = data.algorithm || self.ALGORITHM;
		data.iterations = data.iterations || self.ITERATIONS;

		data.length = data.length || self.LENGTH
		data.saltLength = data.saltLength || self.SALT_LENGTH;
		data.vectorLength = data.vectorLength || self.VECTOR_LENGTH;

		data.hash = self.normalizeHash(data.hash);
		data.algorithm = self.normalizeAlgorithm(data.algorithm);
		data.length = self.normalizeLength(data.algorithm, data.length);

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
		data.length = data.length || self.LENGTH;
		data.algorithm = data.algorithm || self.ALGORITHM;
		data.iterations = data.iterations || self.ITERATIONS;

		data.saltLength = data.saltLength || self.SALT_LENGTH;
		data.vectorLength = data.vectorLength || self.VECTOR_LENGTH;

		data.hash = self.normalizeHash(data.hash);
		data.algorithm = self.normalizeAlgorithm(data.algorithm);
		data.length = self.normalizeLength(data.algorithm, data.length);

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

	Cyrup.randomBytes = RandomBytes;

	Cyrup.pbkdf2 = async function (password, salt, iterations, length, hash) {
		return Pbkdf2(password, salt, iterations, length, hash);
	};

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

	Cyrup.getTag = function (encrypted, length) {
		length = length || 128;
		return encrypted.slice(encrypted.byteLength - ((length + 7) >> 3));
	};

	Cyrup._encrypt = async function (algorithm, key, vector, text) {
		const self = this;
		const cipher = Crypto.createCipheriv(algorithm, key, vector);
		// const encrypted = cipher.update(text, 'utf8', 'hex') + cipher.final('hex');

		let update = cipher.update(text);
		let final = cipher.final();
		let encrypted = Buffer.concat([update, final]);

		const tag = cipher.getAuthTag();
		console.log(self.bufferToHex(tag));

		const t = self.getTag(encrypted);
		console.log(self.bufferToHex(t));
		encrypted = self.bufferToHex(encrypted);

		return encrypted;
	};

	Cyrup._decrypt = async function (algorithm, key, vector, text) {
		const self = this;
		const decipher = Crypto.createDecipheriv(algorithm, key, vector);

		decipher.setAuthTag(tag);

		const decrypted = decipher.update(text, 'hex', 'utf8') + decipher.final('utf8');
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
				salt: salt,
				hash: hash,
				name: 'PBKDF2',
				iterations: iterations
			}, key, {
				name: algorithm,
				length: algorithmLength
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
