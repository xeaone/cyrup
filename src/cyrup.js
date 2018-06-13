
export default {

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

	hasher (data, options) {
		let self = this;

		options = options || {};
		options.type = options.type || 'SHA-256';

		return Promise.resolve().then(function () {
			return self.stringToBuffer(data);
		}).then(function (dataBuffer) {
			return window.crypto.subtle.digest(options.type, dataBuffer);
		}).then(function (hashBuffer) {
			return self.bufferToHex(hashBuffer);
		});
	},

	encrypt (password, text) {
		let self = this;
		let vector = window.crypto.getRandomValues(new Uint8Array(12));
		let options = { name: 'AES-GCM', iv: vector };

		return Promise.resolve().then(function () {
			return self.stringToBuffer(password);
		}).then(function (bufferPassword) {
			return window.crypto.subtle.digest('SHA-256', bufferPassword);
		}).then(function (hash) {
			return Promise.all([
				self.stringToBuffer(text),
				window.crypto.subtle.importKey('raw', hash, options, false, ['encrypt'])
			]);
		}).then(function (items) {
			return window.crypto.subtle.encrypt(options, items[1], items[0]);
		}).then(function (buffer) {
			return Promise.all([
				self.bufferToHex(vector),
				self.bufferToHex(buffer)
			]).then(function (results) {
				return results.join(':');
			});
		});
	},

	decrypt (password, text) {
		let self = this;
		let texts = text.split(':');
		let options = { name: 'AES-GCM' };

		let hexVector = texts[0];
		let hexEncrypted = texts[1];
		let bufferPassword, bufferEncrypted;

		return Promise.all([
			self.hexToBuffer(hexVector),
			self.stringToBuffer(password),
			self.hexToBuffer(hexEncrypted)
		]).then(function (data) {
			options.iv = data[0];
			bufferPassword = data[1];
			bufferEncrypted = data[2];
		}).then(function () {
			return window.crypto.subtle.digest('SHA-256', bufferPassword);
		}).then(function (hash) {
			return window.crypto.subtle.importKey('raw', hash, options, false, ['decrypt']);
		}).then(function (key) {
			return window.crypto.subtle.decrypt(options, key, bufferEncrypted);
		}).then(function (decrypted) {
			return self.bufferToString(decrypted);
		});
	}

}
