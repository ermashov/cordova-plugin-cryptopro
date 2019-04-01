var Cryptopro = function() {};


Cryptopro.prototype.getCertificates = function(success, fail) {
    cordova.exec(success, fail, 'Cryptopro', 'getCertificates', []);
};

if (!window.plugins) {
    window.plugins = {};
}
if (!window.plugins.cryptopro) {
    window.plugins.cryptopro = new Cryptopro();
}

if (module.exports) {
    module.exports = Cryptopro;
}