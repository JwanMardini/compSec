import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class Main {

    public static void main(String[] args) {
        try {
            // Load the keystore
            KeyStore keyStore = KeyStore.getInstance("JKS");
            try (FileInputStream fis = new FileInputStream("Lab1Store")) {
                keyStore.load(fis, "lab1StorePass".toCharArray());
            }

            // Get the private key
            Key privateKey = keyStore.getKey("lab1EncKeys", "lab1KeyPass".toCharArray());

            // Read the encrypted file
            byte[] encryptedFile = Files.readAllBytes(Paths.get("Ciphertext.enc"));

            // Split the encrypted file into parts
            byte[] encryptedKey1 = Arrays.copyOfRange(encryptedFile, 0, 128);
            byte[] encryptedIV = Arrays.copyOfRange(encryptedFile, 128, 256);
            byte[] encryptedKey2 = Arrays.copyOfRange(encryptedFile, 256, 384);
            byte[] encryptedData = Arrays.copyOfRange(encryptedFile, 384, encryptedFile.length);

            // Decrypt Key1, IV, and Key2
            byte[] key1 = decryptRSA(encryptedKey1, privateKey);
            byte[] iv = decryptRSA(encryptedIV, privateKey);
            byte[] key2 = decryptRSA(encryptedKey2, privateKey);

            // Decrypt data
            byte[] plaintext = decryptAES(encryptedData, key1, iv);

            // Read MAC strings and convert them to byte arrays
            String mac1String = new String(Files.readAllBytes(Paths.get("Ciphertext.mac1.txt")));
            String mac2String = new String(Files.readAllBytes(Paths.get("Ciphertext.mac2.txt")));
            byte[] mac1 = hexStringToByteArray(mac1String);
            byte[] mac2 = hexStringToByteArray(mac2String);

            // Verify MAC
            if (verifyMac(plaintext, key2, mac1) || verifyMac(plaintext, key2, mac2)) {
                System.out.println("MAC verification successful.");
            } else {
                System.out.println("MAC verification failed.");
            }

            // Verify Digital Signatures
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new FileInputStream("Lab1Sign.cert"));
            PublicKey publicKey = cert.getPublicKey();
            if (verifySignature("ciphertext.enc.sig1", publicKey, plaintext) ||
                    verifySignature("ciphertext.enc.sig2", publicKey, plaintext)) {
                System.out.println("Signature verification successful.");
            } else {
                System.out.println("Signature verification failed.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] decryptRSA(byte[] data, Key privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    private static byte[] decryptAES(byte[] data, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(data);
    }

    private static boolean verifyMac(byte[] data, byte[] key, byte[] macToVerify) throws Exception {
        Mac mac = Mac.getInstance("HmacMD5");
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacMD5");
        mac.init(keySpec);
        byte[] macBytes = mac.doFinal(data);

        return Arrays.equals(macBytes, macToVerify);
    }

    private static boolean verifySignature(String signatureFile, PublicKey publicKey, byte[] data) throws Exception {
        byte[] signatureBytes = Files.readAllBytes(Paths.get(signatureFile));
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
