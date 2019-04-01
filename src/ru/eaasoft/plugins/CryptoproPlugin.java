package ru.eaasoft.plugins;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;

import android.content.Context;

public class CryptoproPlugin extends CordovaPlugin {

    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) {

        if (!initCSPProviders()) {
            Log.i(Constants.APP_LOGGER_TAG, "Couldn't initialize CSP.");
            return false;
        } // if


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


    /************************ Инициализация провайдера ************************/

        /**
         * Инициализация CSP провайдера.
         *
         * @return True в случае успешной инициализации.
         */
        private boolean initCSPProviders() {

            // Инициализация провайдера CSP. Должна выполняться
            // один раз в главном потоке приложения, т.к. использует
            // статические переменные.
            //
            // 1. Создаем инфраструктуру CSP и копируем ресурсы
            // в папку. В случае ошибки мы, например, выводим окошко
            // (или как-то иначе сообщаем) и завершаем работу.

            int initCode = CSPConfig.init(this);
            boolean initOk = initCode == CSPConfig.CSP_INIT_OK;

            // Если инициализация не удалась, то сообщим об ошибке.
            if (!initOk) {

                switch (initCode) {

                    // Не передан контекст приложения (null). Он необходим,
                    // чтобы произвести копирование ресурсов CSP, создание
                    // папок, смену директории CSP и т.п.
                    case CSPConfig.CSP_INIT_CONTEXT:
                        errorMessage(this, "Couldn't initialize context.");
                        break;

                    /**
                     * Не удается создать инфраструктуру CSP (папки): нет
                     * прав (нарушен контроль целостности) или ошибки.
                     * Подробности в logcat.
                     */
                    case CSPConfig.CSP_INIT_CREATE_INFRASTRUCTURE:
                        errorMessage(this, "Couldn't create CSP infrastructure.");
                        break;

                    /**
                     * Не удается скопировать все или часть ресурсов CSP -
                     * конфигурацию, лицензию (папки): нет прав (нарушен
                     * контроль целостности) или ошибки.
                     * Подробности в logcat.
                     */
                    case CSPConfig.CSP_INIT_COPY_RESOURCES:
                        errorMessage(this, "Couldn't copy CSP resources.");
                        break;

                    /**
                     * Не удается задать рабочую директорию для загрузки
                     * CSP. Подробности в logcat.
                     */
                    case CSPConfig.CSP_INIT_CHANGE_WORK_DIR:
                        errorMessage(this, "Couldn't change CSP working directory.");
                        break;

                    /**
                     * Неправильная лицензия.
                     */
                    case CSPConfig.CSP_INIT_INVALID_LICENSE:
                        errorMessage(this, "Invalid CSP serial number.");
                        break;

                    /**
                     * Не удается создать хранилище доверенных сертификатов
                     * для CAdES API.
                     */
                    case CSPConfig.CSP_TRUST_STORE_FAILED:
                        errorMessage(this, "Couldn't create trust store for CAdES API.");
                        break;

                } // switch

            } // if

            return initOk;
        }

}