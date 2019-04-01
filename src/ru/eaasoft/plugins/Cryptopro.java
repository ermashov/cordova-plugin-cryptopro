package ru.eaasoft.plugins.Cryptopro;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;

import android.content.Context;

public class Cryptopro extends CordovaPlugin {

    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) {
        if (action.equals("getCertificates")) {
            this.getCertificates(callbackContext);
            return true;


        }else if(action.equals("getCertificates")){
            try {
                String alias = args.getString(0);
                this.singCades(alias, callbackContext);
                return true;
            }catch (Exception e){
                return false;
            }

        }
        return false;
    }

    private void getCertificates(CallbackContext callbackContext) {

        String jsonCertificates = "certificate";

        if(jsonCertificates.length() <= 0){
            callbackContext.error("not found");
        }else{
            callbackContext.success(jsonCertificates);
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