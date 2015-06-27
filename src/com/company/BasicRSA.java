import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;



public class BasicRSA{
    public static void main(String[]    args) throws Exception
    {
        byte[]           input = new byte [ ] { (byte)0xab, (byte)0xcd };
        

        // create the keys

        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
                new BigInteger("d46f473a2d746537de2056ae3092c451", 16),
                new BigInteger("11", 16));
        RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(
                new BigInteger("d46f473a2d746537de2056ae3092c451", 16),  
                new BigInteger("57791d5430d593164082036ad8b29fb1", 16));
        Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
		KeyFactory myFactory = KeyFactory.getInstance("RSA", "BC");

		//Actually create key
                RSAPublicKey pubKey = (RSAPublicKey)myFactory.generatePublic(pubKeySpec);
	        RSAPrivateKey privKey = (RSAPrivateKey)myFactory.generatePrivate(privKeySpec);
	        System.out.println("Input: " + CryptoUtils.toHex(input));

       
	   // encryption step
	   cipher.init(Cipher.ENCRYPT_MODE, pubKey);
	   byte[] cipherText = cipher.doFinal(input);
	   System.out.println("ciphertext: " + CryptoUtils.toHex(cipherText));



	   // decryption step
	   cipher.init(Cipher.DECRYPT_MODE, privKey);
	   byte[] plainText = cipher.doFinal(cipherText);
	   System.out.println("plaintext: " + CryptoUtils.toHex(plainText));











    }
}
