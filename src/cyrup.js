
const Cyrup = {

	ENCODING: 'hex',
	ITERATIONS: 999999,

	KEY: 32,
	TAG: 16,
	SALT: 16,
	VECTOR: 12,
	RANDOM: 48,
	HASH: 'sha-512',
	ALGORITHM: 'aes-256-gcm',

	async random (size) {
		const self = this;

		size = size || self.RANDOM;

		const buffer = await self.randomBytes(size);
		const hex = await self.bufferToHex(buffer);

		return hex;
	},

	async hash (item, type) {
		const self = this;

		if (!item) throw new Error('item required');

		type = self.normalizeHash(type || self.HASH);

		const buffer = await self.stringToBuffer(item);
		const bufferHash = await self.createHash(buffer, type);
		const hex = await self.bufferToHex(bufferHash);

		return hex;
	},

	async compare (password, key) {
		const self = this;

		if (!key) throw new Error('key required');
		if (!password) throw new Error('password required');

		const salt = await self.hexToBuffer(key.split(':')[1]);
		const data = await self.key(password, { salt });

		return data === key;
	},

	async key (item, data) {
		const self = this;

		if (!item) throw new Error('item required');

		data = data || {};
		data.size = data.size || self.KEY;
		data.salt = data.salt || self.SALT;
		data.iterations = data.iterations || self.ITERATIONS;
		data.hash = self.normalizeHash(data.hash || self.HASH);

		const [bItem, bSalt] = await Promise.all([

			typeof item === 'string' ?
				self.stringToBuffer(item) : item,

			typeof data.salt === 'string' ?
				self.stringToBuffer(data.salt) :
				typeof data.salt === 'number' ?
					self.randomBytes(data.salt) :
					data.salt
					
		]);

		const bKey = await self.pbkdf2(bItem, bSalt, data.iterations, data.size, data.hash);

		const [hKey, hSalt] = await Promise.all([
			self.bufferToHex(bKey),
			self.bufferToHex(bSalt)
		]);

		return `${hKey}:${hSalt}`;
	},

	async encrypt (data, key, algorithm, vector) {
		const self = this;

		if (!key) throw new Error('key required');
		if (!data) throw new Error('data required');

		key = key.split(':');
		vector = vector || self.VECTOR;
		algorithm = self.normalizeAlgorithm(algorithm || self.ALGORITHM);

		const [bKey, bData, bVector] = await Promise.all([
			self.hexToBuffer(key[0]),
			typeof data === 'string' ? self.stringToBuffer(data) : data,
			typeof vector === 'string' ? self.stringToBuffer(vector) : self.randomBytes(vector)
		]);

		const bEncrypted = await self.cipher(algorithm, bKey, bVector, bData);

		const [hEncrypted, hVector] = await Promise.all([
			self.bufferToHex(bEncrypted),
			self.bufferToHex(bVector)
		]);

		return `${hEncrypted}:${hVector}`;
	},

	async decrypt (data, key, algorithm) {
		const self = this;

		if (!key) throw new Error('key required');
		if (!data) throw new Error('data required');

		algorithm = self.normalizeAlgorithm(algorithm || self.ALGORITHM);

		key = key.split(':');
		data = data.split(':');

		const [bKey, bData, bVector] = await Promise.all([
			self.hexToBuffer(key[0]),
			self.hexToBuffer(data[0]),
			self.hexToBuffer(data[1])
		]);

		const bDecrypted = await self.decipher(algorithm, bKey, bVector, bData);
		const sDecrypted = await self.bufferToString(bDecrypted);

		return sDecrypted;
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

	Cyrup.hexToBuffer = async function (hex) {

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
	};

	Cyrup.bufferToHex = async function (buffer) {
		const bytes = new Uint8Array(buffer);
	 	const hex = new Array(bytes.length);

		for (let i = 0, l = bytes.length; i < l; i++) {
			hex[i] = ( '00' + bytes[i].toString(16) ).slice(-2);
		}

		return hex.join('');
	};

	Cyrup.stringToBuffer = async function (string) {
		const bytes = new Uint8Array(string.length);

		for (let i = 0, l = string.length; i < l; i++) {
			bytes[i] = string.charCodeAt(i);
		}

		return bytes.buffer
	};

    Cyrup.bufferToString = async function (buffer) {
		const bytes = new Uint8Array(buffer);
		const string = new Array(bytes.length);

        for (let i = 0, l = bytes.length; i < l; i++) {
			string[i] = String.fromCharCode(bytes[i]);
        }

        return string.join('');
    };

	Cyrup.createHash = async function (buffer, type) {
		return window.crypto.subtle.digest(type, buffer);
	};

	Cyrup.randomBytes = async function (size) {
		return window.crypto.getRandomValues(new Uint8Array(size));
	};

	Cyrup.pbkdf2 = async function (password, salt, iterations, size, hash) {
		const key = await window.crypto.subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveBits']);

		const bits = await window.crypto.subtle.deriveBits({
			salt,
			iterations,
			name: 'PBKDF2',
			hash: { name: hash }
		}, key, size << 3);

		return new Uint8Array(bits);
	};

	Cyrup.cipher = async function (algorithm, key, vector, data) {
		const self = this;

		const oKey = await window.crypto.subtle.importKey('raw', key, {
			name: algorithm
		}, false, ['encrypt']);

		const encrypted = await window.crypto.subtle.encrypt({
			iv: vector,
			name: algorithm,
			tagLength: self.TAG * 8
		}, oKey, data);

		return encrypted;
	};

	Cyrup.decipher = async function (algorithm, key, vector, data) {
		const self = this;

		const oKey = await window.crypto.subtle.importKey('raw', key, {
			name: algorithm
		}, false, ['decrypt']);

		const decrypted = await window.crypto.subtle.decrypt({
			iv: vector,
			name: algorithm,
			tagLength: self.TAG * 8
		}, oKey, data);

		return decrypted;
	};

}

export default Cyrup;
