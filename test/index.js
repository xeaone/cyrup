const methods = require('./methods.js');

(async function() {

	const name = process.argv[2];

	if (!(name in methods)) {
		const names = Object.keys(methods).join('\n\t');
		console.log(`Argument Required: \n\t${names}`);
		return;
	}

	await methods[name]();

}()).catch(function (error) {
	console.error(error);
});
