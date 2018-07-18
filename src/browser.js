
export default {

	encrypt (password, text, data) {
		const self = this;

		if (!text) throw new Error('text required');
		if (!password) throw new Error('password required');

		data = data || {};
		data.rounds = data.rounds || self.ROUNDS;
		// data.encoding = data.encoding || self.ENCODING;
		data.hashType = data.hashType || self.HASH_TYPE;
		data.algorithm = data.algorithm || self.ALGORITHM;
		data.hashBytes = data.hashBytes || self.HASH_BYTES;
		data.saltBytes = data.saltBytes || self.SALT_BYTES;
		data.vectorBytes = data.vectorBytes || self.VECTOR_BYTES;

		let bSalt, bVector, bText, bPassword;

		return Promise.all([
			self.stringToBuffer(text),
			self.stringToBuffer(password),
			self.randomBytes(data.saltBytes),
			self.randomBytes(data.vectorBytes)
		]).then(function (items) {
			bText = items[0];
			bSalt = items[2];
			bVector = items[3];
			bPassword = items[1];
		}).then(function () {
			return self.pbkdf2(bPassword, bSalt, data.rounds, data.hashType, data.algorithm)
		}).then(function (key) {
			return window.crypto.subtle.encrypt({
				name: data.algorithm,
				iv: bVector
			}, key, bText);
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
		// data.encoding = data.encoding || self.ENCODING;
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
