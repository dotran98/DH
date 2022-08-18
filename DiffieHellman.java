import javax.crypto.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
/*
 * Asssumption:
 *      Suitable key pair has been crated
 *      myPublicKey includes p and g;
 *      PublicKey and PrivateKey refer to DHPublicKey and DHPrivateKey
 *      https://www.javatpoint.com/diffie-hellman-algorithm-in-java
 *   
 */
class DiffieHellman{

    private static PublicKey myPublicKey;
    private static PrivateKey myPrivKey;
    private KeyAgreement keyAgreement;
    private KeyFactory keyFactory;
    private SecretKeySpec sharedAesKey; 
    private Cipher cipherEngine;

    private DiffieHellman(){
        try{
            keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(myPrivKey);
            keyFactory = KeyFactory.getInstance("DH");
            cipherEngine = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e){
            e.printStackTrace();
        }
    }

    /*
     * Take in stored keys
     */
    public static DiffieHellman init(PublicKey publicKey, PrivateKey privKey){
        myPublicKey = publicKey;
        myPrivKey = privKey;
        return new DiffieHellman();
    }

    public static DiffieHellman init(byte[] publicKey, byte[] privateKey) throws InvalidKeyException{
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKey);
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privateKey);
        
        try{
            KeyFactory tmpKeyFactory = KeyFactory.getInstance("DH");
            PrivateKey privKey = tmpKeyFactory.generatePrivate(privKeySpec);
            PublicKey pubKey = tmpKeyFactory.generatePublic(pubKeySpec);
            return DiffieHellman.init(pubKey, privKey);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e){
            e.printStackTrace();
        }
        throw new InvalidKeyException("Key not accepted");
    }

    public static DiffieHellman init(){
        try{
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("DH");
            keygen.initialize(2048);
            KeyPair keypair = keygen.genKeyPair();
            myPrivKey = keypair.getPrivate();
            myPublicKey = keypair.getPublic();
        } catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
        return DiffieHellman.init(myPublicKey, myPrivKey);
    }

    /*
     * Calculate the exchanged key
     * @param key: The DH public key inlcude the value of p and g 
     * @return the exchanged key
     */
    public byte[] calculateExchangeKey(PublicKey key) throws Exception{
        try{
            DHParameterSpec dhParam = ((DHPublicKey)key).getParams();
            return calculateExchangeKey(dhParam.getP(), dhParam.getG());
        } catch (Exception e){
            e.printStackTrace();
        }
        throw new Exception("ERROR!");
    }

    /*
     * Calculate the exchanged key
     * @param p: value of BigInteger p
     * @param g: value of BigInteger g
     * @return the exchanged key
     */
    public byte[] calculateExchangeKey(BigInteger p, BigInteger g) throws Exception{
        DHParameterSpec dhParamSpec = new DHParameterSpec(p, g);
        try{
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("DH");
            keygen.initialize(dhParamSpec);
            KeyPair keypair = keygen.genKeyPair();
            return keypair.getPublic().getEncoded();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e){
            e.printStackTrace();
        }
        throw new Exception("Error!");
    }

    /*
     * Calculate the shared secret to be used in encryption later
     * @param the exchanged key of the other dude
     * @return the shared secret
     */
    public SecretKeySpec calculateSharedSecret(byte[] key) throws Exception{
        try{
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(key);
            PublicKey exchangeKey = keyFactory.generatePublic(x509KeySpec);
            keyAgreement.doPhase(exchangeKey, true);
            byte[] sharedsecret = keyAgreement.generateSecret();
            sharedAesKey = new SecretKeySpec(sharedsecret, 0, 16, "AES");
            return sharedAesKey;

        } catch (InvalidKeyException | InvalidKeySpecException | IllegalStateException e ){
            e.printStackTrace();
        }
        throw new Exception("Key not accepted");
    }

    public byte[] encryptBytes(byte[] toBeEncrypted){
        try{            
            cipherEngine.init(Cipher.ENCRYPT_MODE, sharedAesKey);
            return cipherEngine.doFinal(toBeEncrypted);
        }catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e){
            e.printStackTrace();
        }
        return new byte[]{}; 
    }

    public byte[] decryptBytes(byte[] toBeDecrypted){
        try{
            cipherEngine.init(Cipher.DECRYPT_MODE, sharedAesKey);
            return cipherEngine.doFinal(toBeDecrypted);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e){
            e.printStackTrace();
        }
        return new byte[]{};
    }
}
