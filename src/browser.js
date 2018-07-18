
export default {

	encrypt (password, text, data) {

		if (!text) throw new Error('text required');
		if (!password) throw new Error('password required');

		const self = this;

		let salt, vector, passwordBuffer;

		data = data || {};
		data.rounds = data.rounds || self.ROUNDS;
		data.encoding = data.encoding || self.ENCODING;
		data.hashType = data.hashType || self.HASH_TYPE;
		data.algorithm = data.algorithm || self.ALGORITHM;
		data.hashBytes = data.hashBytes || self.HASH_BYTES;
		data.saltBytes = data.saltBytes || self.SALT_BYTES;
		data.vectorBytes = data.vectorBytes || self.VECTOR_BYTES;

		return Promise.resolve().then(function () {
			return Promise.all([
				self.stringToBuffer(password),
				self.randomBytes(self.SALT_BYTES),
				self.randomBytes(self.VECTOR_BYTES)
			]);
		}).then(function (items) {
			salt = items[1];
			vector = items[2];
			passwordBuffer = items[0];
		}).then(function () {
			return Promise.all([
				self.stringToBuffer(text),
				self.pbkdf2(passwordBuffer, salt, data.rounds, data.hashType, data.algorithm)
			]);
		}).then(function (items) {
			const textBuffer = items[0];
			const key = items[1];
			return window.crypto.subtle.encrypt({
				name: self.ALGORITHM,
				iv: vector
			}, key, textBuffer);
		}).then(function (encrypted) {
			return Promise.all([
				self.bufferToHex(encrypted),
				self.bufferToHex(vector),
				self.bufferToHex(salt),
			]).then(function (results) {
				return results.join(':');
			});
		});
	},

	decrypt (password, encrypted, data) {

		if (!password) throw new Error('password required');
		if (!encrypted) throw new Error('encrypted required');

	 	const self = this;
		const encrypteds = encrypted.split(':');
		const textHex = encrypteds[0];
		const vectorHex = encrypteds[1];
		const saltHex = encrypteds[2];

		let passwordBuffer, textBuffer, vectorBuffer, saltBuffer;

		data = data || {};
		data.rounds = data.rounds || self.ROUNDS;
		data.encoding = data.encoding || self.ENCODING;
		data.hashType = data.hashType || self.HASH_TYPE;
		data.algorithm = data.algorithm || self.ALGORITHM;
		data.hashBytes = data.hashBytes || self.HASH_BYTES;

		return Promise.all([
			self.hexToBuffer(textHex),
			self.hexToBuffer(vectorHex),
			self.hexToBuffer(saltHex),
			self.stringToBuffer(password)
		]).then(function (items) {
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

}
