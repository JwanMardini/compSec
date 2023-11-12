import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;

public class RSATest {
    RSAPublicKey myPublic;
    RSAPrivateKey myPrivate;
    Cipher enc;
    Cipher dec;

    byte[] plaintext;
    byte[] ciphertext;
    public void generateKeys(){
        try{
            //create random key
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(512);
            KeyPair myPair = keyGen.generateKeyPair();
            myPublic = (RSAPublicKey)myPair.getPublic();
            myPrivate = (RSAPrivateKey)myPair.getPrivate();
        }
        catch(Exception ex){
            System.out.println("Problems");
        }
    }

    public void createCipher(){
        //initiates encryptionBox1 and decryptionBox2
        try{
            enc = Cipher.getInstance("RSA");
            enc.init(Cipher.ENCRYPT_MODE,myPublic);
            dec = Cipher.getInstance("RSA");
            dec.init(Cipher.DECRYPT_MODE,myPrivate);
        }
        catch(Exception ex){
            System.out.println("Problems");
        }
    }

    public void encryptText(String message){
        try{
            plaintext = message.getBytes(); //transform message to byte[]
            ciphertext = new byte[enc.getOutputSize(plaintext.length)];
            int ctLength;
            ctLength=enc.update(plaintext,0,plaintext.length,ciphertext,0); 
            enc.doFinal(ciphertext,ctLength);
        }
        catch(Exception ex){
            System.out.println("Problems");
        }
        
    } //getOutputSize() returns the length in bytes that the output buffer would need. The actual output length of the next update or doFinal may be smaller .
        //int doFinal(byte[] output, int outputOffset)

    /*public void encryptText(String message){
        try{
            plaintext = message.getBytes(); // Transform message to byte[]
            ciphertext = enc.doFinal(plaintext);
        } catch(Exception ex){
            System.out.println("Encryption Problems: " + ex.getMessage());
        }
    }*/
          
    

    public String decryptText(){
        try{
            byte[] decrypted = new byte[dec.getOutputSize(ciphertext.length)];
            int decLength=
            dec.doFinal(ciphertext,0,ciphertext.length,decrypted);
            String decryptedString=new String(decrypted,0,decLength);
            return decryptedString;
        }
        catch(Exception ex){
            System.out.println("Problems");
        }
        return "";
    }

    /*public String decryptText(){
        try{
            byte[] decrypted = dec.doFinal(ciphertext);
            return new String(decrypted, "UTF-8"); // Assuming UTF-8 encoding
        } catch(Exception ex){
            System.out.println("Decryption Problems: " + ex.getMessage());
        }
        return "";
    }*/
    
}
