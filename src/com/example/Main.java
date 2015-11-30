package com.example;

import javax.net.ssl.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.ResourceBundle;
import java.util.logging.Logger;
import java.util.stream.Stream;
/*
public class Main {

    public static void main(String[] args) {

        try {
            URL url = new URL("https://mxoccmga01.noam.cemexnet.com:14101/certinfo/certinfo");

            HttpURLConnection urlConnection = (HttpURLConnection)url.openConnection();

            KeyStore ks = KeyStore.getInstance("JKS");
            InputStream fileIn =  Main.class.getResourceAsStream("se.jks");

            if (fileIn == null)
                throw new FileNotFoundException("Object store file sample.p12 not found");

            ks.load(fileIn, "secret".toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, "secret".toCharArray());
            SSLContext sc = SSLContext.getInstance("TLSv1");
            sc.init(kmf.getKeyManagers(), null, null);

            //FileOu
            //mks.store("c:/temp/foo", "secret".toCharArray());

            if (urlConnection instanceof HttpsURLConnection) {
                ((HttpsURLConnection)urlConnection).setSSLSocketFactory(sc.getSocketFactory());
            }

            InputStream in = urlConnection.getInputStream();

            byte[] buff = new byte[1024];
            int len = in.read(buff);
            while (len > 0) {
                System.out.write(buff, 0, len);
                len = in.read(buff);
            }
        } catch(Exception e) {
            e.printStackTrace();
        }
    }
}
*/
public class Main {

    private static final Logger logger = Logger.getLogger(Main.class.getName());
    private static final String LINE_BREAKER = System.getProperty("line.separator");

    private static final String CERTIFACATE_FILE = "C:/Temp/MutualAtuhSSLClient/resources/com/example/certexp.pfx";
    private static final String CERTIFACATE_PASS = "secret";
    private static final String CERTIFACATE_ALIAS = "{bdc37bb5-18a0-4016-9519-8fed9a451aa6}";
    private static final String TARGET_URL = "https://mxoccmga01.noam.cemexnet.com:14101/certinfo/certinfo";


    public static void main(String[] args) {
        String targetURL = TARGET_URL;
        URL url;
        HttpsURLConnection connection = null;
        BufferedReader bufferedReader = null;
        InputStream is = null;

        try {
            //Create connection
            url = new URL(targetURL);
            //Uncomment this in case server demands some unsafe operations
            //System.setProperty("sun.security.ssl.allowUnsafeRenegotiation", "true");
            connection = (HttpsURLConnection) url.openConnection();

            connection.setRequestMethod("GET");
            //connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            //connection.setRequestProperty("Content-Language", "en-US");

            SSLSocketFactory sslSocketFactory = getFactory(new File(CERTIFACATE_FILE), CERTIFACATE_PASS, CERTIFACATE_ALIAS);
            connection.setSSLSocketFactory(sslSocketFactory);

            //Process response
            is = connection.getInputStream();

            bufferedReader = new BufferedReader(new InputStreamReader(is));
            String line;
            StringBuffer lines = new StringBuffer();
            while ((line = bufferedReader.readLine()) != null) {
                lines.append(line).append(LINE_BREAKER);
            }
            logger.info("response from " + targetURL + ":" + LINE_BREAKER + lines);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static SSLSocketFactory getFactory(File pKeyFile, String pKeyPassword, String certAlias) throws Exception {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        KeyStore keyStore = KeyStore.getInstance("pkcs12");

        InputStream keyInput = new FileInputStream(pKeyFile);
        keyStore.load(keyInput, pKeyPassword.toCharArray());


        Enumeration enumeration = keyStore.aliases();
        while(enumeration.hasMoreElements()) {
            String alias = (String)enumeration.nextElement();
            System.out.println("alias name: " + alias);
            Certificate certificate = keyStore.getCertificate(alias);
            System.out.println(certificate.toString());

        }
        keyInput.close();
        keyManagerFactory.init(keyStore, pKeyPassword.toCharArray());

        //Replace the original KeyManagers with the AliasForcingKeyManager
        KeyManager[] kms = keyManagerFactory.getKeyManagers();
        for (int i = 0; i < kms.length; i++) {
            if (kms[i] instanceof X509KeyManager) {
                kms[i] = new AliasForcingKeyManager((X509KeyManager) kms[i], certAlias);
            }
        }

        SSLContext context = SSLContext.getInstance("TLSv1.2");
        context.init(kms, null, null);
        return context.getSocketFactory();
    }

    /*
     * This wrapper class overwrites the default behavior of a X509KeyManager and
     * always render a specific certificate whose alias matches that provided in the constructor
     */
    private static class AliasForcingKeyManager implements X509KeyManager {

        X509KeyManager baseKM = null;
        String alias = null;

        public AliasForcingKeyManager(X509KeyManager keyManager, String alias) {
            baseKM = keyManager;
            this.alias = alias;
        }

        /*
         * Always render the specific alias provided in the constructor
         */
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return alias;
        }

        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return baseKM.chooseServerAlias(keyType, issuers, socket);
        }

        public X509Certificate[] getCertificateChain(String alias) {
            return baseKM.getCertificateChain(alias);
        }

        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return baseKM.getClientAliases(keyType, issuers);
        }

        public PrivateKey getPrivateKey(String alias) {
            return baseKM.getPrivateKey(alias);
        }

        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return baseKM.getServerAliases(keyType, issuers);
        }
    }
}