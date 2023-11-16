import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import javax.crypto.Mac;

public class Hash {
    private MessageDigest md;
    private Mac mac;
    private Signature mySign;
    private Signature myVerify;

    public void createMessageDigest(){
    //create the message digest
        try {
            md=MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Problems");
    }}

    public String calculateHash(String message){
        byte[] data=message.getBytes();
        md.update(data);
        byte[] hashVal=md.digest();
        return ByteTool.toHex(hashVal, hashVal.length);
    }

    public void createMac(){
        try {
            mac=Mac.getInstance("HmacMD5");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Problems");
        }
    }

    public String calculateMac(String message,Key key){
        byte[] macVal=null;
        try {
            mac.init(key);
            mac.update(message.getBytes());
            macVal=mac.doFinal();
            return(DatatypeConverter.printHexBinary(macVal));
        } catch (InvalidKeyException e) {
            System.out.println("Problems");
        }
        return "";
        }

    public void createSignature(){
        try {
            mySign=Signature.getInstance("SHA1withRSA");
            myVerify=Signature.getInstance("SHA1withRSA");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Problem");
            System.out.println(e.toString());
        }
    }

    public byte[] Sign(String message,PrivateKey prK){
        try {
            mySign.initSign(prK);
            mySign.update(message.getBytes());
            return mySign.sign();
        } catch (Exception e) {
            System.out.println("Problems");
            System.out.println(e.toString());
        }
        return null;
    }

    public boolean Verify(String message, PublicKey puK, byte[] sig){
        try {
            myVerify.initVerify(puK);
            myVerify.update(message.getBytes());
            return myVerify.verify(sig);
        } catch (Exception e) {
            System.out.println("Problems");
            System.out.println(e.toString());
        }
        return false;
    }

    
}
