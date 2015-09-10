package com.example;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;
import java.util.stream.Stream;

public class Main {

    public static void main(String[] args) {

        try {
            URL url = new URL("https://google.com");
            HttpURLConnection urlConnection = (HttpURLConnection)url.openConnection();

            KeyStore ks = KeyStore.getInstance("PKCS12");
            FileInputStream fis = new FileInputStream("C:\\temp\\Lighthouse-SDK\\samples\\android\\map-certificate-viewer\\src\\main\\assets\\sample.p12");
            ks.load(fis, "secret".toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, "secret".toCharArray());
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(kmf.getKeyManagers(), null, null);

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
