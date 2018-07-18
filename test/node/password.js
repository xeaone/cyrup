const Cyrup = require('./cyrup.js');

(async function() {
	const password = 'secret';
	const text = 'hello world';

	const passwordHash = await Cyrup.hashPassword(password);
	console.log(passwordHash);

	const passwordValid = await Cyrup.comparePassword(password, passwordHash);
	console.log(`valid password: ${passwordValid}`);

	const passwordInvalid = await Cyrup.comparePassword('wrong', passwordHash);
	console.log(`invalid password: ${passwordInvalid}`);

}()).catch(function (error) {
	console.error(error);
});
