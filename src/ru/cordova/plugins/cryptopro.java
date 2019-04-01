package ru.eaasoft.cordova-plugin-cryptopro;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;

import android.content.Context;

public class Cryptopro extends CordovaPlugin {

    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) {
        if (action.equals("getCertificates")) {
            String message = args.getString(0);
            this.getCertificates(message, callbackContext);
            return true;


        }else if(action.equals("getCertificates")){
            String alias = args.getString(0);
            this.singCades(alias, callbackContext);
            return true;
        }
        return false;
    }

    private void getCertificates(CallbackContext callbackContext) {

        String jsonCertificates = "certificate";

        if(jsonCertificates.length <= 0){
            callbackContext.error("not found");
        }else{
            CallbackContext.success(jsonCertificates);
        }

    }

    private void singCades(String alias, CallbackContext callbackContext) {
        if (alias != null && alias.length() > 0) {
            callbackContext.success(alias);
        } else {
            callbackContext.error("Expected one non-empty string argument.");
        }
    }

}