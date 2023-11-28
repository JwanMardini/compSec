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


    /**
     * Stores a secret key in a JCEKS keystore file.
     * 
     * @param storeFilename the filename of the keystore file
     * @param storePassword the password that protects the keystore file
     * @param key the secret key to be stored
     * @param alias the alias to be associated with the secret key
     * @param keyPassword the password that protects the secret key
     */
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

    
        /**
         * Represents a secret (symmetric) key.
         */
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
