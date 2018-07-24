
if (typeof module === 'undefined') {
	module = {};
} else {
	Cyrup = require('./cyrup.js');
}

const TEXT = 'hello world';
const PASSWORD = 'secret';

module.exports = {

	async password () {

		const hPassword = await Cyrup.password(PASSWORD);
		console.log(`password: ${hPassword}`);

		const valid = await Cyrup.valid(PASSWORD, hPassword);
		console.log(`valid: ${valid}`);

	},

	async crypt () {

		console.time('key');
		const key = await Cyrup.key({ item: PASSWORD });
		console.timeEnd('key');

		console.time('encrypt');
		const encrypted = await Cyrup.encrypt({ item: TEXT, key: key });
		console.timeEnd('encrypt');

		console.log(`encrypted: ${encrypted}`);

		console.time('decrypt');
		const decrypted = await Cyrup.decrypt({ item: encrypted, key: key });
		console.timeEnd('decrypt');

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
