var Cryptopro = function() {};


Cryptopro.prototype.getCertificates = function(success, fail) {
    cordova.exec(success, fail, 'Cryptopro', 'getCertificates', []);
};

Cryptopro.prototype.singCades = function(params, success, fail) {
    cordova.exec(success, fail, 'Cryptopro', 'singCades', [
        params.keyStoreType,
        params.alias,
        params.pin,
        params.data,
        params.detached,
    ]);
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


/*
window.plugins.cryptopro.getCertificates(function(cert){
            alert(cert);
        },function(error){
            alert(error);
        })

window.plugins.cryptopro.singCades({
            keyStoreType:"Aktiv Rutoken ECP BT 1",
            alias:"29824913@2019-03-29-АО НПФ СОГЛАСИЕ",
            pin:"1234567890",
            data:"UHJpdmV0",
            detached:"N",
        },
        function(cert){
            alert(cert);
        },function(error){
            alert(error);
        })
 */

