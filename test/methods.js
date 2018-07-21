
if (typeof module === 'undefined') {
	module = {};
} else {
	Cyrup = require('./cyrup.js');
}

module.exports = {

	async crypt () {
		const password = 'secret';
		const text = 'hello wrold';

		const encrypted = await Cyrup.encrypt({ password, item: text });
		console.log(`encrypted: ${encrypted}`);

		const decrypted = await Cyrup.decrypt({ password, item: encrypted });
		console.log(`decrypted: ${decrypted}`);

	},

	async hash () {
		const hash = await Cyrup.hash({ item: 'hash is good' });
		console.log(`hash: ${hash}`);
	},

	async secret () {
		const secret = await Cyrup.secret();
		console.log(`secret: ${secret}`);
	}

};
