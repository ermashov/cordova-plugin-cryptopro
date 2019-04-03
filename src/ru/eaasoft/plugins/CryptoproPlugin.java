package ru.eaasoft.plugins;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import android.util.Log;
import ru.CryptoPro.JCSP.CSPConfig;
import ru.CryptoPro.JCSP.JCSP;
import ru.CryptoPro.JCSP.support.BKSTrustStore;

import ru.CryptoPro.ssl.util.cpSSLConfig;
import ru.cprocsp.ACSP.tools.common.Constants;

import ru.CryptoPro.AdES.tools.AlgorithmUtility;
import ru.CryptoPro.CAdES.CAdESConfig;
import ru.CryptoPro.JCP.JCP;

import ru.CryptoPro.JCP.ASN.CertificateExtensions.GeneralName;
import ru.CryptoPro.JCP.ASN.CertificateExtensions.GeneralNames;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.*;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.*;

import ru.CryptoPro.JCP.params.OID;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;

import org.json.JSONObject;

import java.security.Security;
import java.io.File;

import java.security.KeyStore;
import java.util.Enumeration;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import ru.CryptoPro.reprov.RevCheck;
import com.objsys.asn1j.runtime.Asn1BerDecodeBuffer;
import com.objsys.asn1j.runtime.Asn1BerEncodeBuffer;
import com.objsys.asn1j.runtime.Asn1Null;
import com.objsys.asn1j.runtime.Asn1ObjectIdentifier;
import com.objsys.asn1j.runtime.Asn1OctetString;
import com.objsys.asn1j.runtime.Asn1Type;
import com.objsys.asn1j.runtime.Asn1UTCTime;
import ru.CryptoPro.JCP.KeyStore.JCPPrivateKeyEntry;
import ru.CryptoPro.JCP.tools.Encoder;
import ru.CryptoPro.JCP.tools.Decoder;

import android.content.Context;

public class CryptoproPlugin extends CordovaPlugin {

    private String KeyStoreType = "Aktiv Rutoken ECP BT 1";

    public static final String STR_CMS_OID_SIGNED = "1.2.840.113549.1.7.2";
    public static final String STR_CMS_OID_DATA = "1.2.840.113549.1.7.1";
    public static final String STR_CMS_OID_CONT_TYP_ATTR = "1.2.840.113549.1.9.3";
    public static final String STR_CMS_OID_DIGEST_ATTR = "1.2.840.113549.1.9.4";
    public static final String STR_CMS_OID_SIGN_TYM_ATTR = "1.2.840.113549.1.9.5";

    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) {

        Context context = this.cordova.getActivity().getApplicationContext();

        if (!initCSPProviders(context)) {
            callbackContext.error("Couldn't initialize CSP.");
            return false;
        } // if

        initJavaProviders(context);

        if (action.equals("getCertificates")) {
            this.getCertificates(callbackContext);
            return true;
        }else if(action.equals("singCades")){
            try {
                String keyStoreType = args.getString(0);
                String alias = args.getString(1);
                String pin = args.getString(2);
                String data = args.getString(3);
                Boolean detached = false;

                if(args.getString(4).equals("Y")){
                    detached = true;
                }

                this.singCades(keyStoreType, alias, pin, data, detached, callbackContext);
                return true;
            }catch (Exception e){
                callbackContext.error(e.getMessage());
                return false;
            }

        }
        return false;
    }

    private void getCertificates(CallbackContext callbackContext) {

        String jsonCertificates = "";

        try {

            JSONArray jsonArrObjectCert = new JSONArray();

            JSONObject jsonObjectCert;

            KeyStore keyStore1 = KeyStore.getInstance(KeyStoreType, JCSP.PROVIDER_NAME);
            keyStore1.load(null, null);
            Enumeration<String> aliases = keyStore1.aliases();
            String keyAlgorithm;
            String alias;
            X509Certificate cert;
            X500Name x500name;
            while (aliases.hasMoreElements()) {
                alias = aliases.nextElement();
                jsonObjectCert = new JSONObject();
                cert = (X509Certificate) keyStore1.getCertificate(alias);
                x500name = new JcaX509CertificateHolder(cert).getSubject();
                if (cert != null) {
                    keyAlgorithm = cert.getPublicKey().getAlgorithm();
                    jsonObjectCert.put("name",
                            x500name.getRDNs(BCStyle.CN)[0].getFirst().getValue()
                                    + " (" + keyAlgorithm + ")"
                    );
                    jsonObjectCert.put("alias",alias);
                    jsonArrObjectCert.put(jsonObjectCert);
                }
            }

            jsonCertificates += jsonArrObjectCert.toString();

            } catch (Exception e) {
                Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
            }

        if(jsonCertificates.length() <= 0){
            callbackContext.error("not found cert or container");
        }else{
            callbackContext.success(jsonCertificates);
        }

    }

    public void singCades(String inKeyStoreType,
                            String inAlias,
                            String inPin,
                            String inData,
                            boolean detached,
                            CallbackContext callbackContext
    )
    {

        try {

            String signature;

            byte[] data = fromBase64(inData);

            if(inKeyStoreType.length() <= 0){
                inKeyStoreType = KeyStoreType;
            }

            CertificateInfo cInfo = load(
                    true,
                    inKeyStoreType,
                    inAlias,
                    inPin.toCharArray()
            );

            PrivateKey privateKey = cInfo.getPrivateKey();
            X509Certificate certificate = cInfo.getCertificate();
            AlgorithmSelector algorithm = cInfo.getAlgorithm();

            byte[] signatureByte = create(
                    data,
                    false,
                    new PrivateKey[]{privateKey},
                    new Certificate[]{certificate},
                    detached,
                    false,
                    algorithm
            );

            signature = (new String(toBase64(signatureByte))).replaceAll("\\n", "");

            callbackContext.success(signature);

        }catch (Exception e){
            callbackContext.error(e.getMessage());
        }
    }

    /**
     * Загрузка ключа и сертификата из контейнера. Если параметр
     * askPinInWindow равен true, то переданный сюда пароль не
     * имеет значения, он будет запрошен в окне CSP только при
     * непосредственной работе с ключом. Если же параметр равен
     * false, то этот пароль будет задан однажды и, если он
     * правильный, больше не понадобится вводить его в окне CSP.
     *
     * @param askPinInWindow True, если будем вводить пин-код в
     * окне.
     * @param storeType Тип ключевого контейнера.
     * @param alias Алиас ключа.
     * @param password Пароль к ключу.
     */
    public CertificateInfo load(
            boolean askPinInWindow,
            String storeType,
            String alias,
            char[] password
    ) throws Exception {

        PrivateKey privateKey;
        X509Certificate certificate;

        try {
            KeyStore keyStore = KeyStore.getInstance(storeType, JCSP.PROVIDER_NAME);

            keyStore.load(null, password);

            Enumeration<String> aliases = keyStore.aliases();

            if(!aliases.hasMoreElements()){
                throw new Exception("Not found token or certificate");
            }

            KeyStore.ProtectionParameter protectedParam = new KeyStore.PasswordProtection(password);

            JCPPrivateKeyEntry entry = (JCPPrivateKeyEntry) keyStore.getEntry(alias, protectedParam);

            privateKey = entry.getPrivateKey();

            certificate = (X509Certificate) entry.getCertificate();

            //Log.e("DN - ",  certificate.getSubjectDN().toString());


            return new CertificateInfo(privateKey, certificate);

        }catch (Exception error){
            throw error;
        }
    }

    byte[] create(byte[] data, boolean isExternalDigest, PrivateKey[]
            keys, Certificate[] certs, boolean detached, boolean addSignCertV2, AlgorithmSelector algorithmSelector)
            throws Exception {

        boolean needSignAttributes = true;

        final ContentInfo all = new ContentInfo();
        all.contentType = new Asn1ObjectIdentifier(
                new OID(STR_CMS_OID_SIGNED).value);

        final SignedData cms = new SignedData();
        all.content = cms;
        cms.version = new CMSVersion(1);

        cms.digestAlgorithms = new DigestAlgorithmIdentifiers(1);
        final DigestAlgorithmIdentifier a = new DigestAlgorithmIdentifier(
                new OID(algorithmSelector.getDigestAlgorithmOid()).value);
        a.parameters = new Asn1Null();
        cms.digestAlgorithms.elements[0] = a;


        // Нельзя сделать подпись совмещенной, если нет данных, а
        // есть только хэш с них.

        if (isExternalDigest && !detached) {
            throw new Exception("Signature is attached but external " +
                    "digest is available only (not data)");
        } // if

        if (detached) {
            cms.encapContentInfo = new EncapsulatedContentInfo(
                    new Asn1ObjectIdentifier(
                            new OID(STR_CMS_OID_DATA).value), null);
        } // if
        else {
            cms.encapContentInfo = new EncapsulatedContentInfo(
                    new Asn1ObjectIdentifier(new OID(STR_CMS_OID_DATA).value),
                    new Asn1OctetString(data));
        } // else

        // Сертификаты.

        final int nCerts = certs.length;
        cms.certificates = new CertificateSet(nCerts);
        cms.certificates.elements = new CertificateChoices[nCerts];

        for (int i = 0; i < cms.certificates.elements.length; i++) {

            final ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate certificate =
                    new ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate();

            final Asn1BerDecodeBuffer decodeBuffer =
                    new Asn1BerDecodeBuffer(certs[i].getEncoded());

            certificate.decode(decodeBuffer);
            cms.certificates.elements[i] = new CertificateChoices();
            cms.certificates.elements[i].set_certificate(certificate);

        } // for


        final Signature signature = Signature.getInstance(
                algorithmSelector.getSignatureAlgorithmName());

        byte[] sign;

        // Подписанты (signerInfos).


        final int nSigners = keys.length;
        cms.signerInfos = new SignerInfos(nSigners);
        for (int i = 0; i < cms.signerInfos.elements.length; i++) {

            cms.signerInfos.elements[i] = new SignerInfo();
            cms.signerInfos.elements[i].version = new CMSVersion(1);
            cms.signerInfos.elements[i].sid = new SignerIdentifier();

            final byte[] encodedName = ((X509Certificate) certs[i])
                    .getIssuerX500Principal().getEncoded();

            final Asn1BerDecodeBuffer nameBuf =
                    new Asn1BerDecodeBuffer(encodedName);

            final Name name = new Name();
            name.decode(nameBuf);

            final CertificateSerialNumber num = new CertificateSerialNumber(
                    ((X509Certificate) certs[i]).getSerialNumber());
            cms.signerInfos.elements[i].sid.set_issuerAndSerialNumber(
                    new IssuerAndSerialNumber(name, num));

            cms.signerInfos.elements[i].digestAlgorithm =
                    new DigestAlgorithmIdentifier(
                            new OID(algorithmSelector.getDigestAlgorithmOid()).value);

            cms.signerInfos.elements[i].digestAlgorithm.parameters = new Asn1Null();

            String keyAlgOid = AlgorithmUtility.keyAlg2SignatureOid(keys[0].getAlgorithm());


            cms.signerInfos.elements[i].signatureAlgorithm =
                    new SignatureAlgorithmIdentifier(new OID(keyAlgOid).value);

            cms.signerInfos.elements[i].signatureAlgorithm.parameters = new Asn1Null();

            byte[] data2hash;

            if (needSignAttributes) {

                final int kMax = addSignCertV2 ? 4 : 3;
                cms.signerInfos.elements[i].signedAttrs = new SignedAttributes(kMax);

                // content-type

                int k = 0;
                cms.signerInfos.elements[i].signedAttrs.elements[k] =
                        new Attribute(new OID(STR_CMS_OID_CONT_TYP_ATTR).value,
                                new Attribute_values(1));

                final Asn1Type cont_type = new Asn1ObjectIdentifier(
                        new OID(STR_CMS_OID_DATA).value);

                cms.signerInfos.elements[i].signedAttrs
                        .elements[k].values.elements[0] = cont_type;

                // signing-time


                k += 1;
                cms.signerInfos.elements[i].signedAttrs.elements[k] =
                        new Attribute(new OID(STR_CMS_OID_SIGN_TYM_ATTR).value,
                                new Attribute_values(1));

                final Time time = new Time();
                final Asn1UTCTime UTCTime = new Asn1UTCTime();

                // Текущая дата календаря.
                UTCTime.setTime(Calendar.getInstance());
                time.set_utcTime(UTCTime);

                cms.signerInfos.elements[i].signedAttrs
                        .elements[k].values.elements[0] = time.getElement();

                // message-digest

                k += 1;
                cms.signerInfos.elements[i].signedAttrs.elements[k] =
                        new Attribute(new OID(STR_CMS_OID_DIGEST_ATTR).value,
                                new Attribute_values(1));
                final byte[] message_digest_b;


                // Если вместо данных у нас хеш, то сразу его передаем,
                // ничего не вычисляем.

                if (isExternalDigest) {
                    message_digest_b = data;
                } // if
                else {

                    if (detached) {
                        message_digest_b = digest(data,
                                algorithmSelector.getDigestAlgorithmName());
                    } // if
                    else {
                        message_digest_b = digest(cms.encapContentInfo.eContent.value,
                                algorithmSelector.getDigestAlgorithmName());
                    } // else

                } // else

                final Asn1Type message_digest = new Asn1OctetString(message_digest_b);

                cms.signerInfos.elements[i].signedAttrs
                        .elements[k].values.elements[0] = message_digest;

                // Добавление signingCertificateV2 в подписанные аттрибуты,
                // чтобы подпись стала похожа на CAdES-BES.

                if (addSignCertV2) {

                    // Аттрибут с OID'ом id_aa_signingCertificateV2.

                    k += 1;
                    cms.signerInfos.elements[i].signedAttrs.elements[k] =
                            new Attribute(new OID(ALL_PKIX1Explicit88Values
                                    .id_aa_signingCertificateV2).value,
                                    new Attribute_values(1));

                    // Идентификатор алгоритма, который использовался
                    // для хеширования контекста сертификата ключа подписи.

                    final DigestAlgorithmIdentifier digestAlgorithmIdentifier =
                            new DigestAlgorithmIdentifier(
                                    new OID(algorithmSelector.getDigestAlgorithmOid()).value);

                    // Хеш сертификата ключа подписи.

                    final CertHash certHash = new CertHash(digest(certs[i].getEncoded(),
                            algorithmSelector.getDigestAlgorithmName()));

                    // Issuer name из сертификата ключа подписи.

                    GeneralName generalName = new GeneralName();
                    generalName.set_directoryName(name);

                    GeneralNames generalNames = new GeneralNames();
                    generalNames.elements = new GeneralName[1];
                    generalNames.elements[0] = generalName;

                    // Комбинируем издателя и серийный номер.

                    IssuerSerial issuerSerial = new IssuerSerial(generalNames, num);

                    ESSCertIDv2 essCertIDv2 = new ESSCertIDv2(digestAlgorithmIdentifier,
                            certHash, issuerSerial);

                    _SeqOfESSCertIDv2 essCertIDv2s = new _SeqOfESSCertIDv2(1);
                    essCertIDv2s.elements = new ESSCertIDv2[1];
                    essCertIDv2s.elements[0] = essCertIDv2;

                    // Добавляем сам аттрибут.

                    SigningCertificateV2 signingCertificateV2 =
                            new SigningCertificateV2(essCertIDv2s);

                    cms.signerInfos.elements[i].signedAttrs
                            .elements[k].values.elements[0] = signingCertificateV2;

                } // if

                // Данные для хэширования.

                Asn1BerEncodeBuffer encBufSignedAttr = new Asn1BerEncodeBuffer();
                cms.signerInfos.elements[i].signedAttrs.encode(encBufSignedAttr);
                data2hash = encBufSignedAttr.getMsgCopy();

            } // if
            else {
                data2hash = data;
            } // else

            signature.initSign(keys[i]);
            signature.update(data2hash);
            sign = signature.sign();

            cms.signerInfos.elements[i].signature = new SignatureValue(sign);

        } // for

        // CMS подпись.


        final Asn1BerEncodeBuffer asnBuf = new Asn1BerEncodeBuffer();
        all.encode(asnBuf, true);
        return asnBuf.getMsgCopy();

    }

    /**
     * Инициализация CSP провайдера.
     *
     * @return True в случае успешной инициализации.
     */
    private boolean initCSPProviders(Context context) {

            // Инициализация провайдера CSP. Должна выполняться
            // один раз в главном потоке приложения, т.к. использует
            // статические переменные.
            //
            // 1. Создаем инфраструктуру CSP и копируем ресурсы
            // в папку. В случае ошибки мы, например, выводим окошко
            // (или как-то иначе сообщаем) и завершаем работу.

            int initCode = CSPConfig.init(context);
            boolean initOk = initCode == CSPConfig.CSP_INIT_OK;

            // Если инициализация не удалась, то сообщим об ошибке.
            if (!initOk) {

                switch (initCode) {

                    // Не передан контекст приложения (null). Он необходим,
                    // чтобы произвести копирование ресурсов CSP, создание
                    // папок, смену директории CSP и т.п.
                    case CSPConfig.CSP_INIT_CONTEXT:
                        Log.i(Constants.APP_LOGGER_TAG, "Couldn't initialize context.");
                        //errorMessage(this, "Couldn't initialize context.");
                        break;

                    /**
                     * Не удается создать инфраструктуру CSP (папки): нет
                     * прав (нарушен контроль целостности) или ошибки.
                     * Подробности в logcat.
                     */
                    case CSPConfig.CSP_INIT_CREATE_INFRASTRUCTURE:
                        Log.i(Constants.APP_LOGGER_TAG, "Couldn't create CSP infrastructure.");
                        //errorMessage(this, "Couldn't create CSP infrastructure.");
                        break;

                    /**
                     * Не удается скопировать все или часть ресурсов CSP -
                     * конфигурацию, лицензию (папки): нет прав (нарушен
                     * контроль целостности) или ошибки.
                     * Подробности в logcat.
                     */
                    case CSPConfig.CSP_INIT_COPY_RESOURCES:
                        Log.i(Constants.APP_LOGGER_TAG, "Couldn't copy CSP resources.");
                        //errorMessage(this, "Couldn't copy CSP resources.");
                        break;

                    /**
                     * Не удается задать рабочую директорию для загрузки
                     * CSP. Подробности в logcat.
                     */
                    case CSPConfig.CSP_INIT_CHANGE_WORK_DIR:
                        Log.i(Constants.APP_LOGGER_TAG, "Couldn't change CSP working directory.");
                        //errorMessage(this, "Couldn't change CSP working directory.");
                        break;

                    /**
                     * Неправильная лицензия.
                     */
                    case CSPConfig.CSP_INIT_INVALID_LICENSE:
                        Log.i(Constants.APP_LOGGER_TAG, "Invalid CSP serial number.");
                        //errorMessage(this, "Invalid CSP serial number.");
                        break;

                    /**
                     * Не удается создать хранилище доверенных сертификатов
                     * для CAdES API.
                     */
                    case CSPConfig.CSP_TRUST_STORE_FAILED:
                        Log.i(Constants.APP_LOGGER_TAG, "Couldn't create trust store for CAdES API.");
                        //errorMessage(this, "Couldn't create trust store for CAdES API.");
                        break;

                } // switch

            } // if

            return initOk;
        }

    /**
     * Добавление нативного провайдера Java CSP,
     * SSL-провайдера и Revocation-провайдера в
     * список Security. Инициализируется JCPxml,
     * CAdES.
     *
     * Происходит один раз при инициализации.
     * Возможно только после инициализации в CSPConfig!
     *
     */
    private void initJavaProviders(Context context) {

        // Загрузка Java CSP (хеш, подпись, шифрование, генерация контейнеров).

        if (Security.getProvider(JCSP.PROVIDER_NAME) == null) {
            Security.addProvider(new JCSP());
        } // if

        // Загрузка JTLS (TLS).

        // Необходимо переопределить свойства, чтобы использовались
        // менеджеры из cpSSL, а не Harmony.

        Security.setProperty("ssl.KeyManagerFactory.algorithm",
                ru.CryptoPro.ssl.Provider.KEYMANGER_ALG);
        Security.setProperty("ssl.TrustManagerFactory.algorithm",
                ru.CryptoPro.ssl.Provider.KEYMANGER_ALG);

        Security.setProperty("ssl.SocketFactory.provider",
                "ru.CryptoPro.ssl.SSLSocketFactoryImpl");
        Security.setProperty("ssl.ServerSocketFactory.provider",
                "ru.CryptoPro.ssl.SSLServerSocketFactoryImpl");

        if (Security.getProvider(ru.CryptoPro.ssl.Provider.PROVIDER_NAME) == null) {
            Security.addProvider(new ru.CryptoPro.ssl.Provider());
        } // if

        // Провайдер хеширования, подписи, шифрования по умолчанию.
        cpSSLConfig.setDefaultSSLProvider(JCSP.PROVIDER_NAME);

        // Загрузка Revocation Provider (CRL, OCSP).

        if (Security.getProvider(RevCheck.PROVIDER_NAME) == null) {
            Security.addProvider(new RevCheck());
        } // if

        // Инициализация XML DSig (хеш, подпись).

        //XmlInit.init();

        // Параметры для Java TLS и CAdES API.

        // Провайдер CAdES API по умолчанию.
        CAdESConfig.setDefaultProvider(JCSP.PROVIDER_NAME);

        // Включаем возможность онлайновой проверки статуса сертификата.
        System.setProperty("com.sun.security.enableCRLDP", "true");
        System.setProperty("com.ibm.security.enableCRLDP", "true");

        // Настройки TLS для генерации контейнера и выпуска сертификата
        // в УЦ 2.0, т.к. обращение к УЦ 2.0 будет выполняться по протоколу
        // HTTPS и потребуется авторизация по сертификату. Указываем тип
        // хранилища с доверенным корневым сертификатом, путь к нему и пароль.

        final String trustStorePath = context.getApplicationInfo().dataDir + File.separator +
                BKSTrustStore.STORAGE_DIRECTORY + File.separator + BKSTrustStore.STORAGE_FILE_TRUST;

        final String trustStorePassword = String.valueOf(BKSTrustStore.STORAGE_PASSWORD);
        //Log.d(Constants.APP_LOGGER_TAG, "Default trust store: " + trustStorePath);

        System.setProperty("javax.net.ssl.trustStoreType", BKSTrustStore.STORAGE_TYPE);
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", trustStorePassword);

    }

    /**
     * Конвертация в base64.
     *
     * @param data Исходные данные.
     * @return конвертированная строка.
     */
    private String toBase64(byte[] data) {
        Encoder enc = new Encoder();
        return enc.encode(data);
    }

    private byte[] fromBase64(String data) throws Exception{
        Decoder decoder = new Decoder();
        return decoder.decodeBuffer(data);
    }

    /**
     * @param bytes Хэшируемые данные.
     * @param digestAlgorithmName Алгоритм хэширования.
     * @return хэш данных.
     * @throws Exception
     */
    private byte[] digest(byte[] bytes, String digestAlgorithmName)
            throws Exception {

        final ByteArrayInputStream stream = new ByteArrayInputStream(bytes);
        final MessageDigest digest = MessageDigest.getInstance(digestAlgorithmName);
        final DigestInputStream digestStream = new DigestInputStream(stream, digest);

        while (digestStream.available() != 0) {
            digestStream.read();
        } // while

        return digest.digest();
    }

}


class CertificateInfo {
    private static PrivateKey privateKey = null;
    private static X509Certificate certificate = null;
    private static AlgorithmSelector algorithmSelector = null;

    CertificateInfo(PrivateKey paramPrivateKey,X509Certificate paramCertificate)
            throws IOException {
        privateKey = paramPrivateKey;
        certificate = paramCertificate;

        String keyAlgorithm = certificate.getPublicKey().getAlgorithm();

        if ((keyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_DEGREE_NAME))) {
            algorithmSelector = AlgorithmSelector.getInstance(AlgorithmSelector.DefaultProviderType.pt2001);
        } // if
        else if (keyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_256_NAME)) {
            algorithmSelector = AlgorithmSelector.getInstance(AlgorithmSelector.DefaultProviderType.pt2012Short);
        } // else
        else if (keyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_512_NAME)) {
            algorithmSelector = AlgorithmSelector.getInstance(AlgorithmSelector.DefaultProviderType.pt2012Long);
        }else {
            throw new NullPointerException("Algorithm not support");
        }
    }

    public PrivateKey getPrivateKey(){
        return privateKey;
    }

    public X509Certificate getCertificate(){
        return certificate;
    }
    public AlgorithmSelector getAlgorithm(){
        return algorithmSelector;
    }
}

class AlgorithmSelector {

    /**
     * Возможные типы провайдеров.
     */
    public enum DefaultProviderType {ptUnknown, pt2001, pt2012Short, pt2012Long};

    /**
     * Тип провайдера.
     */
    private DefaultProviderType providerType;

    /**
     * Алгоритм подписи.
     */
    private String signatureAlgorithmName = null;

    /**
     * Алгоритм хеширования.
     */
    private String digestAlgorithmName = null;

    /**
     * OID алгоритма хеширования.
     */
    private String digestAlgorithmOid = null;

    /**
     * Конструктор.
     *
     * @param type Тип провайдера.
     * @param signAlgName Алгоритм подписи.
     * @param digestAlgName Алгоритм хеширования.
     * @param digestAlgOid OID алгоритма хеширования.
     */
    protected AlgorithmSelector(DefaultProviderType type,
                                String signAlgName, String digestAlgName, String digestAlgOid) {

        providerType = type;
        signatureAlgorithmName = signAlgName;

        digestAlgorithmName = digestAlgName;
        digestAlgorithmOid = digestAlgOid;

    }

    /**
     * Получение типа провайдера.
     *
     * @return тип провайдера.
     */
    public DefaultProviderType getProviderType() {
        return providerType;
    }

    /**
     * Получение алгоритма подписи.
     *
     * @return алгоритм подписи.
     */
    public String getSignatureAlgorithmName() {
        return signatureAlgorithmName;
    }

    /**
     * Получение алгоритма хеширования.
     *
     * @return алгоритм хеширования.
     */
    public String getDigestAlgorithmName() {
        return digestAlgorithmName;
    }

    /**
     * Получение OID'а алгоритма хеширования.
     *
     * @return OID алгоритма.
     */
    public String getDigestAlgorithmOid() {
        return digestAlgorithmOid;
    }

    /**
     * Получение списка алгоритмов для данного провайдера.
     *
     * @param pt Тип провайдера.
     * @return настройки провайдера.
     */
    public static AlgorithmSelector getInstance(DefaultProviderType pt) {

        switch (pt) {

            case pt2001:      return new AlgorithmSelector_2011();
            case pt2012Short: return new AlgorithmSelector_2012_256();
            case pt2012Long:  return new AlgorithmSelector_2012_512();
        }

        throw new IllegalArgumentException();
    }

    /**
     * Получение типа провайдера по его строковому представлению.
     *
     * @param val Тип в виде числа.
     * @return тип в виде значения из перечисления.
     */
    public static DefaultProviderType find(int val) {

        switch (val) {
            case 0: return DefaultProviderType.pt2001;
            case 1: return DefaultProviderType.pt2012Short;
            case 2: return DefaultProviderType.pt2012Long;
        } // switch

        throw new IllegalArgumentException();

    }

    //------------------------------------------------------------------------------------------------------------------

    /**
     * Класс с алгоритмами ГОСТ 2001.
     *
     */
    private static class AlgorithmSelector_2011 extends AlgorithmSelector {

        /**
         * Конструктор.
         *
         */
        public AlgorithmSelector_2011() {
            super(DefaultProviderType.pt2001, JCP.GOST_EL_SIGN_NAME,
                    JCP.GOST_DIGEST_NAME, JCP.GOST_DIGEST_OID);
        }

    }

    /**
     * Класс с алгоритмами ГОСТ 2012 (256).
     *
     */
    private static class AlgorithmSelector_2012_256 extends AlgorithmSelector {

        /**
         * Конструктор.
         *
         */
        public AlgorithmSelector_2012_256() {
            super(DefaultProviderType.pt2012Short, JCP.GOST_SIGN_2012_256_NAME,
                    JCP.GOST_DIGEST_2012_256_NAME, JCP.GOST_DIGEST_2012_256_OID);
        }

    }

    /**
     * Класс с алгоритмами ГОСТ 2012 (512).
     *
     */
    private static class AlgorithmSelector_2012_512 extends AlgorithmSelector {

        /**
         * Конструктор.
         *
         */
        public AlgorithmSelector_2012_512() {
            super(DefaultProviderType.pt2012Long, JCP.GOST_SIGN_2012_512_NAME,
                    JCP.GOST_DIGEST_2012_512_NAME, JCP.GOST_DIGEST_2012_512_OID);
        }

    }

}