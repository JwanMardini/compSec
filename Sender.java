import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Sender {
    private Cipher encoder;
    private SecretKeySpec myKey;

    public Sender()throws Exception{
    //create the cipher
    //getInstance(”Algorithm name”)
    encoder=Cipher.getInstance("AES");

    }

    public void setKey(byte[] key) throws Exception{
        //creates the key using provided bytes
        //and initiate the cipher for encryption
        myKey= new SecretKeySpec(key,"AES");

        //init(opMode,key) – opMode determines if encryption or decryption
        encoder.init(Cipher.ENCRYPT_MODE, myKey);
    }

    public byte[] send(byte[] message) throws Exception{
        //doFinal() – Input final part of data – Generate final output – Make cipher ready for new input
        return encoder.doFinal(message);
    }
}

