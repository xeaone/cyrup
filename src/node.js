
const Util = require('util');
const Crypto = require('crypto');

const Pbkdf2 = Util.promisify(Crypto.pbkdf2);
const RandomBytes = Util.promisify(Crypto.randomBytes);

module.exports = {

	ROUNDS: 99999,
	ENCODING: 'hex',
	ALGORITHM: 'aes-256-gcm',

	SALT_BYTES: 16,
	HASH_BYTES: 32,
	VECTOR_BYTES: 12,
	SECRET_BYTES: 48,

	HASH_TYPE: 'sha512',

	pbkdf2: Pbkdf2,
	randomBytes: RandomBytes,

	async hashPassword (password, data) {
		const self = this;

		data = data || {};
		data.rounds = data.rounds || self.ROUNDS;
		data.encoding = data.encoding || self.ENCODING;
		data.hashType = data.hashType || self.HASH_TYPE;
		data.hashBytes = data.hashBytes || self.HASH_BYTES;
		data.saltBytes = data.saltBytes || self.SALT_BYTES;

		const salt = await RandomBytes(data.saltBytes);
		const hash = await Pbkdf2(password, salt, data.rounds, data.hashBytes, data.hashType);

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

		const verify = await Pbkdf2(password, salt, rounds, hashBytes, data.hashType);

		return verify.toString('binary') === hash;
	},

	async secret (data) {
		const self = this;

		data = data || {};
		data.bytes = data.bytes || self.SECRET_BYTES;
		data.encoding = data.encoding || self.ENCODING;

		const bytes = await RandomBytes(data.bytes);

		return bytes.toString(data.encoding);
	},

	async hash (text, data) {
		const self = this;

		data = data || {};
		data.encoding = data.encoding || self.ENCODING;
		data.hashType = data.hashType || self.HASH_TYPE;

		return Crypto.createHash(data.hashType).update(text).digest(data.encoding);
	},

	async encrypt (password, text, data) {
		const self = this;

		data = data || {};
		data.rounds = data.rounds || self.ROUNDS;
		data.encoding = data.encoding || self.ENCODING;
		data.hashType = data.hashType || self.HASH_TYPE;
		data.algorithm = data.algorithm || self.ALGORITHM;
		data.hashBytes = data.hashBytes || self.HASH_BYTES;
		data.saltBytes = data.saltBytes || self.SALT_BYTES;
		data.vectorBytes = data.vectorBytes || self.VECTOR_BYTES;

		const salt = await RandomBytes(data.saltBytes);
		const vector = await RandomBytes(data.vectorBytes);
		const key = await Pbkdf2(password, salt, data.rounds, data.hashBytes, data.hashType);
		const cipher = Crypto.createCipheriv(data.algorithm, key, vector);

		// const data = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
		const encrypted = cipher.update(text, 'utf8', data.encoding) + cipher.final(data.encoding);
		const tag = cipher.getAuthTag();

		return `${encrypted}:${vector.toString(data.encoding)}:${salt.toString(data.encoding)}:${tag.toString(data.encoding)}`;
	},

	async decrypt (password, encrypted, data) {
		const self = this;

		data = data || {};
		data.rounds = data.rounds || self.ROUNDS;
		data.encoding = data.encoding || self.ENCODING;
		data.hashType = data.hashType || self.HASH_TYPE;
		data.algorithm = data.algorithm || self.ALGORITHM;
		data.hashBytes = data.hashBytes || self.HASH_BYTES;

		const encrypteds = encrypted.split(':');
		const text = encrypteds[0];
		const vector = Buffer.from(encrypteds[1], data.encoding);
		const salt = Buffer.from(encrypteds[2], data.encoding);
		const tag = Buffer.from(encrypteds[3], data.encoding);

		const key = await Pbkdf2(password, salt, data.rounds, data.hashBytes, data.hashType);
		const decipher = Crypto.createDecipheriv(data.algorithm, key, vector);

		decipher.setAuthTag(tag);

		const result = decipher.update(text, data.encoding, 'utf8') + decipher.final('utf8');

		return result;
	}

};
