
export default {

	KEY_LENGTH: 32,
	ITERATIONS: 999,
	SALT_LENGTH: 64,
	VECTOR_LENGTH: 12,

	HASH: 'SHA-256',

	ALGORITHM_NAME: 'AES-GCM',
	ALGORITHM_LENGTH: 256,

	hexToBuffer (hex) {
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
	},

	bufferToHex (buffer) {
		return Promise.resolve().then(function () {

			let bytes = new Uint8Array(buffer);
			let hexes = [];

			for(let i = 0, l = bytes.length; i < l; i++) {

				let hex = bytes[i].toString(16);
				let pad = ('00' + hex).slice(-2);

				hexes.push(pad);
			}

			return hexes.join('');
		});
	},

	stringToBuffer (string) {
		return Promise.resolve().then(function () {
			let bytes = new Uint8Array(string.length);

			for (let i = 0, l = string.length; i < l; i++) {
				bytes[i] = string.charCodeAt(i);
			}

			return bytes.buffer
		});
	},

    bufferToString (buffer) {
        let data = '';

        for (let i = 0; i < buffer.byteLength; i++) {
             data += String.fromCharCode(buffer[i]);
        }

        return data;
    },

	/*bufferToString: function (buffer) {
		return Promise.resolve().then(function () {
			let char2, char3, c;
			let bytes = new Uint8Array(buffer);

			let i = 0;
			let out = '';
			let length = bytes.length;

			while (i < length) {

				c = bytes[i++];

				switch (c >> 4) {
					case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:
						// 0xxxxxxx
						out += String.fromCharCode(c);
					break;
					case 12: case 13:
						// 110x xxxx 10xx xxxx
						char2 = bytes[i++];
						out += String.fromCharCode(((c & 0x1F) << 6) | (char2 & 0x3F));
					break;
					case 14:
						// 1110 xxxx 10xx xxxx 10xx xxxx
						char2 = bytes[i++];
						char3 = bytes[i++];
						out += String.fromCharCode(((c & 0x0F) << 12) | ((char2 & 0x3F) << 6) | ((char3 & 0x3F) << 0));
					break;
				}

			}

			return out;
		});
	},*/

	generateKey (password, salt, iterations, length, hash) {
		const self = this;

		if (!salt) throw new Error('salt required');

		return Promise.resolve().then(function () {
			return window.crypto.subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']);
		}).then(function (key) {

			var derived = {
				name: self.ALGORITHM_NAME,
				length: length || self.ALGORITHM_LENGTH
			};

			var algorithm = {
				salt: salt,
				name: 'PBKDF2',
				hash: hash || self.HASH,
				iterations: iterations || self.ITERATIONS,
			};

			return window.crypto.subtle.deriveKey(algorithm, key, derived, false, ['encrypt', 'decrypt']);
		});
	},

	hasher (data, options) {
		const self = this;

		options = options || {};
		options.type = options.type || self.HASH;

		return Promise.resolve().then(function () {
			return self.stringToBuffer(data);
		}).then(function (dataBuffer) {
			return window.crypto.subtle.digest(options.type, dataBuffer);
		}).then(function (hashBuffer) {
			return self.bufferToHex(hashBuffer);
		});
	},

	encrypt (password, text) {
		const self = this;
		const salt = window.crypto.getRandomValues(new Uint8Array(self.SALT_LENGTH));
		const vector = window.crypto.getRandomValues(new Uint8Array(self.VECTOR_LENGTH));

		return Promise.resolve().then(function () {
			return self.stringToBuffer(password);
		}).then(function (passwordBuffer) {
			// return window.crypto.subtle.digest(self.HASH, passwordBuffer);
		// }).then(function (passwordHashBuffer) {
			return Promise.all([
				self.stringToBuffer(text),
				// self.generateKey(passwordHashBuffer, salt)
				self.generateKey(passwordBuffer, salt)
			]);
		}).then(function (items) {
			return window.crypto.subtle.encrypt({
				length: self.ALGORITHM_LENGTH,
				name: self.ALGORITHM_NAME,
				iv: vector
			}, items[1], items[0]);
		}).then(function (data) {
			return Promise.all([
				self.bufferToHex(data),
				self.bufferToHex(vector),
				self.bufferToHex(salt),
			]).then(function (results) {
				return results.join(':');
			});
		});
	},

	decrypt (password, text) {
	 	const self = this;
		const texts = text.split(':');

		const dataHex = texts[0];
		const vectorHex = texts[1];
		const saltHex = texts[2];
		let passwordBuffer, dataBuffer, vectorBuffer, saltBuffer;

		// password = new TextEncoder().encode(password);

		return Promise.all([
			self.hexToBuffer(dataHex),
			self.hexToBuffer(vectorHex),
			self.hexToBuffer(saltHex),
			self.stringToBuffer(password)
		]).then(function (data) {
			passwordBuffer = data[3];
			saltBuffer = data[2];
			vectorBuffer = data[1];
			dataBuffer = data[0];
		}).then(function () {
			// return window.crypto.subtle.digest(self.HASH, passwordBuffer);
		// }).then(function (passwordHashBuffer) {
			// return self.generateKey(passwordHashBuffer, saltBuffer);
			return self.generateKey(passwordBuffer, saltBuffer);
		}).then(function (key) {
			return window.crypto.subtle.decrypt({
				length: self.ALGORITHM_LENGTH,
				name: self.ALGORITHM_NAME,
				iv: vectorBuffer
			}, key, dataBuffer);
		}).then(function (decrypted) {
			return self.bufferToString(decrypted);
		});
	}

}
