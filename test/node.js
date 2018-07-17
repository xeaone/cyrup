const Cyrup = require('../dis/cyrup.node.js');

(async function() {
	const password = 'secret';
	const text = 'hello world';

	// const encrypted = await Cyrup.encrypt(password, text);
	//
	// const decrypted = await Cyrup.decrypt(password, encrypted);
	// console.log(`decrypted: ${decrypted}`);

	const passwordHash = await Cyrup.hashPassword(password);
	const passwordValid = await Cyrup.verifyPassword(password, passwordHash);
	console.log(`password: ${passwordValid}`);

}()).catch(function (error) {
	console.error(error);
});
