import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;

import javax.crypto.SecretKey;

public class KeyManagement {
    /**
     * Creates a new keystore with the specified filename and password.
     * If the keystore file does not exist, it will be created.
     * If the keystore file already exists, it will be overwritten.
     * @param filename the name of the keystore file
     * @param password the password to protect the keystore
     */
    public void createKeystore(String filename,char[] password){
        try {
            KeyStore myStore=KeyStore.getInstance("JCEKS");
            myStore.load(null,null); //first time no file or password
            FileOutputStream storeFile=new FileOutputStream(filename);
            myStore.store(storeFile,password);
            storeFile.close();
        } catch (Exception e) {
            System.out.println("Next time I would maybe throw the exception instead");
        e.printStackTrace();
        }
    }


    public void storeKey(String storeFilename,char[]
        storePassword,SecretKey key,String alias,char[] keyPassword){
        try {
            KeyStore myStore=KeyStore.getInstance("JCEKS");
            FileInputStream loadFile=new FileInputStream(storeFilename);
            myStore.load(loadFile,storePassword); //filename and password that protects the keystore
            loadFile.close();
            KeyStore.SecretKeyEntry skEntry=new KeyStore.SecretKeyEntry(key);
            myStore.setEntry(alias, skEntry, new
            KeyStore.PasswordProtection(keyPassword));
            FileOutputStream storeFile=new FileOutputStream(storeFilename);
            myStore.store(storeFile,storePassword);
            storeFile.close();
            } catch (Exception e) {
                System.out.println("Next time I would maybe throw the exception instead");
                e.printStackTrace();
            }
        }

    
        public SecretKey loadKey(String storeFilename,char[]
        storePassword,String alias,char[] keyPassword){
        try {
            //start by loading keystore
            KeyStore myStore=KeyStore.getInstance("JCEKS");
            FileInputStream loadFile=new FileInputStream(storeFilename);
            myStore.load(loadFile,storePassword); //filename and password that protects the keystore
            loadFile.close();
            //load key
            SecretKey theKey=(SecretKey)myStore.getKey(alias,keyPassword);
            return theKey;
        } catch (Exception e) {
            System.out.println("Next time I would maybe throw the exception instead");
            e.printStackTrace();
        }
        return null;
    }
    
}
