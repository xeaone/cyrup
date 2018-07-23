
if (typeof module === 'undefined') {
	module = {};
} else {
	Cyrup = require('./cyrup.js');
}

module.exports = {

	async crypt () {
		const text = 'hello wrold';

		const key = await Cyrup.key({ item: 'secret' });

		const encrypted = await Cyrup.encrypt({ item: text, key: key });
		console.log(`encrypted: ${encrypted}`);

		const decrypted = await Cyrup.decrypt({ item: encrypted, key: key });
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
