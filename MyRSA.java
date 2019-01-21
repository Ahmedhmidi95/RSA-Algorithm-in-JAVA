import java.io.*;
import java.math.*;
import javax.crypto.*;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.io.File;
import java.nio.file.Files;


/** 
 * Cette classe propose des méthodes permettant de crypter et décrypter des 
 * messages avec l'algorithme RSA. Le message doit cependant être plus petit
 * que KEY_SIZE.
 */
public class MyRSA {
  public final static int KEY_SIZE = 2048;  // [512..2048]

  private RSAPublicKey publicKey;
  private RSAPrivateKey privateKey;
  
  
  public MyRSA() {
  }
  public RSAPublicKey getPublicKey() {
    return publicKey;
  }
  public byte[] getPublicKeyInBytes() {
    return publicKey.getEncoded();
  }
  public RSAPrivateKey getPrivateKey() {
    return privateKey;
  }
  public byte[] getPrivateKeyInBytes() {
    return privateKey.getEncoded();
  }  
  public void setPublicKey(RSAPublicKey publicKey) {
    this.publicKey = publicKey;
  }
  public void setPublicKey(byte[] publicKeyData) {
    try {
      X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyData);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      publicKey = (RSAPublicKey)keyFactory.generatePublic(publicKeySpec);
    }
    catch (Exception e) {System.out.println(e);} 
  }
  public void setPrivateKey(RSAPrivateKey privateKey) {
    this.privateKey = privateKey;
  }
  public void setPrivateKey(byte[] privateKeyData) {
    try {
      PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyData);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      privateKey = (RSAPrivateKey)keyFactory.generatePrivate(privateKeySpec);
    }
    catch (Exception e) {System.out.println(e);} 
  }    
  public void generateKeyPair() {
    try {
      KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
      keyPairGen.initialize(KEY_SIZE, new SecureRandom());
      KeyPair kp = keyPairGen.generateKeyPair();
      publicKey = (RSAPublicKey)kp.getPublic();
      privateKey = (RSAPrivateKey)kp.getPrivate();
    }
    catch (Exception e) {System.out.println(e);} 
  }
  public byte[] crypt(byte[] plaintext) {
    return crypt(new BigInteger(addOneByte(plaintext))).toByteArray();
  } 
  public byte[] crypt(String plaintext) {
    return crypt(plaintext.getBytes());
  }
  public byte[] decryptInBytes(byte[] plaintextEncrypted) {
    return removeOneByte(decrypt(new BigInteger(plaintextEncrypted)).toByteArray());
  }    
  public String decryptInString(byte[] plaintextEncrypted) {
    return new String(decryptInBytes(plaintextEncrypted));
  }

  /**
   * Cette méthode permet de tester le bon fonctionnement des autres.
   */
  public static void main(String[] args) {
    //String plaintext = args[0];
    byte[] fileBytes = null;
    String plaintext="";
    //Open file as bytes
    try{
      File file = new File("bigfile.txt");
      fileBytes = Files.readAllBytes(file.toPath());
      plaintext = new String(fileBytes, "UTF-8");
    }
    catch(IOException e){
      System.out.println(e.toString());
      System.out.println("Cannot open file: bigFile.txt !");
      return;
    }

    //Crypt
    System.out.println("1/ Plain text from file: " + plaintext);
    System.out.println("\n --------------------------------------\n");
    MyRSA rsa = new MyRSA();
    rsa.generateKeyPair();
    byte[] publicKey = rsa.getPublicKeyInBytes();
    byte[] privateKey = rsa.getPrivateKeyInBytes();
    byte[] plaintextEncrypted = rsa.crypt(plaintext);   
    System.out.println("2/ Plain text crypted = " + new BigInteger(plaintextEncrypted));
    System.out.println("\n --------------------------------------\n");

    rsa.setPublicKey(publicKey);
    rsa.setPrivateKey(privateKey); 

    //decrypt  
    String plaintext2 = rsa.decryptInString(plaintextEncrypted);
    System.out.println("3/ plaintext Decrypted = " + plaintext2);
    System.out.println("\n --------------------------------------\n");
    
    if (!plaintext2.equals(plaintext)) System.out.println("Error: plaintext2 != plaintext");
    System.out.println("\n --------------------------------------\n");

    System.out.println(" Public Key = " + new BigInteger(publicKey));
    System.out.println(" Private Key = " + new BigInteger(privateKey));
  }
  

  private BigInteger crypt(BigInteger plaintext) {
    return plaintext.modPow(publicKey.getPublicExponent(), publicKey.getModulus());
  }
  
  
  private BigInteger decrypt(BigInteger plaintextEncrypted) {
    return plaintextEncrypted.modPow(privateKey.getPrivateExponent(), privateKey.getModulus());
  }            
  

  /**
   * Ajoute un byte de valeur 1 au début du message afin d'éviter que ce dernier
   * ne corresponde pas à un nombre négatif lorsqu'il sera transformé en
   * BigInteger.
   */
  private static byte[] addOneByte(byte[] input) {
    byte[] result = new byte[input.length+1];
    result[0] = 1;
    for (int i = 0; i < input.length; i++) {
      result[i+1] = input[i];
    }
    return result;
  }
  
  
  /**
   * Retire le byte ajouté par la méthode addOneByte.
   */
  private static byte[] removeOneByte(byte[] input) {
    byte[] result = new byte[input.length-1];
    for (int i = 0; i < result.length; i++) {
      result[i] = input[i+1];
    }
    return result;
  }
}