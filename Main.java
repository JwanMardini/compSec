import java.util.Arrays;

public class Main {
    public static void main(String[] args) throws Exception {
        /*Sender sender = new Sender();
        Receiver receiver = new Receiver();

        byte[] message={0,0,1,2,3,4,5,6,7,6,5,4,2,3,8,9};
        byte[] key={1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4};
        byte[] ciphertext;
        byte[] decrypted;

        sender.setKey(key);
        receiver.setKey(key);

        ciphertext=sender.send(message);
        decrypted=receiver.receive(ciphertext);

        System.out.println("Message: " + Arrays.toString(message));
        System.out.println("Ciphertext: " + Arrays.toString(ciphertext));
        System.out.println("Decrypted: " + Arrays.toString(decrypted));*/

        RSATest rsa = new RSATest();
        rsa.generateKeys(); // Generate RSA key pair

        // Encrypt a message
        String originalMessage = "Hello, RSA!";
        rsa.createCipher();
        rsa.encryptText(originalMessage);
        System.out.println("Original Message: " + originalMessage);

        // Display the encrypted message
        byte[] encryptedMessage = rsa.ciphertext;
        System.out.println("Encrypted Message: " + Arrays.toString(encryptedMessage));

        // Decrypt the encrypted message
        String decryptedMessage = rsa.decryptText();
        System.out.println("Decrypted Message: " + decryptedMessage);

        
    }
}
