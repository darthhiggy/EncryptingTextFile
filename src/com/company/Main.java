package com.company;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.util.Scanner;

public class Main
{
    private static String KEY_FILENAME="AESKey.bin";
    private static int ITERATIONS=1000;

    public static void main(String[] args) throws Exception
    {
        String input;
        String output;
        String password;
        int choice = 1;
        Scanner scan = new Scanner(System.in);
        while(choice != 0)
        {
            System.out.println("Choose 1: to generate a new key, 2: to encrypt a file, 3: to decrypt a file, 0: to exit");
            choice = scan.nextInt();
            scan.nextLine();

            if (choice == 1)
            {
                System.out.println("Enter password: ");
                password = scan.nextLine();

                createKey(password);
                Key newKey = loadKey(password);
            }
            else if (choice == 2)
            {
                System.out.println("Enter password: ");
                password = scan.nextLine();
                System.out.println("Enter file path and name for input file: ");
                input = scan.nextLine();
                System.out.println("Enter file path and name for output file: ");
                output = scan.nextLine();
                encrypt(password, input, output);
            }
            else if (choice == 3)
            {
                System.out.println("Enter password: ");
                password = scan.nextLine();
                System.out.println("Enter file path and name for input file: ");
                input = scan.nextLine();
                System.out.println("Enter file path and name for output file: ");
                output = scan.nextLine();
                decrypt(password, input, output);
            }
            else if (choice == 0)
            {
                System.out.println("Exiting application...");
            }

            else
            {
                System.out.println("Incorrect input, please try again");
            }
        }
    }

    private static void createKey(String pass) throws Exception
    {
        System.out.println("Generating a AES key...");
        Key aeskey = CryptoUtils.createAESKey(256, new SecureRandom());
        System.out.println(CryptoUtils.toHex(aeskey.getEncoded()));
        // use password-based encryption to encrypt key
        System.out.println("Encrypting Key...");
        char[] password = pass.toCharArray();
        byte[] salt = new byte[8];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        PBEKeySpec pbeSpec = new PBEKeySpec(password, salt, ITERATIONS);
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES");
        Key skey = keyFact.generateSecret(pbeSpec);
        Cipher cDec = Cipher.getInstance("PBEWithSHAAnd3KeyTripleDES");
        cDec.init(Cipher.ENCRYPT_MODE, skey);
        byte[] encryptedKeyBytes = cDec.doFinal(aeskey.getEncoded());
        // print out encrypted key in hex
        System.out.println(CryptoUtils.toHex(encryptedKeyBytes));
        // store the key in the file
        FileOutputStream fos = new FileOutputStream(KEY_FILENAME);
        fos.write(salt);
        fos.write(encryptedKeyBytes);
        fos.close();

    }

    private static byte[] readFromFile(String textFile) throws IOException
    {
        FileInputStream fis = new FileInputStream(textFile);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int i = 0;
        while((i = fis.read()) != -1)
        {
            baos.write(i);
        }
        fis.close();
        byte[] message = baos.toByteArray();
        baos.close();
        fis.close();
        return message;
    }

    private static Key loadKey(String pass) throws Exception
    {
        byte[] salt = new byte[8];
        byte[] fullText = readFromFile(KEY_FILENAME);
        byte[] encryptedKeyBytes = new byte[(fullText.length-8)];
        System.arraycopy(fullText, 0, salt, 0, 8);
        System.arraycopy(fullText, 8, encryptedKeyBytes, 0, (fullText.length-8));
        System.out.println(CryptoUtils.toHex(encryptedKeyBytes));
        char[] password = pass.toCharArray();
        PBEKeySpec pbeSpec = new PBEKeySpec(password, salt, ITERATIONS);
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES");
        Key skey = keyFact.generateSecret(pbeSpec);
        Cipher cDec = Cipher.getInstance("PBEWithSHAAnd3KeyTripleDES");
        cDec.init(Cipher.DECRYPT_MODE, skey);
        byte[] decryptedKeyBytes = cDec.doFinal(encryptedKeyBytes);
        Key returnKey = new SecretKeySpec(decryptedKeyBytes, "AES");
        System.out.println(CryptoUtils.toHex(returnKey.getEncoded()));
        return returnKey;
    }

    private static void encrypt(String password, String fileInput, String fileOutput) throws Exception
    {
        //load key
        Key aesKey = loadKey(password);
        //initialize cipher
        Cipher Enc = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        //create random IV with 16 bytes
        byte[] ivBytes = new byte[16];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(ivBytes);
        //create file input and output streams
        FileInputStream fis = new FileInputStream(fileInput);
        FileOutputStream fos = new FileOutputStream(fileOutput);
        //write iv as the first 16 bytes in the file
        fos.write(ivBytes);
        //create IvParameterSpec
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        //initialize cipher
        Enc.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        //CipherInputStream and CipherOutputStream provide conveient wrappers around standard input and
        //output stream that automatically encrypt and decrypt

        CipherOutputStream cos = new CipherOutputStream(fos, Enc);
        System.out.println("Encrypting the file ...");
        int theByte = 0;
        while((theByte = fis.read()) != -1)
        {
            //System.out.print(theByte + " ");
            cos.write(theByte);
        }
        fis.close();
        cos.close();

    }

    private static void decrypt(String password, String fileInput, String fileOutput) throws Exception
    {
        //load key
        Key aesKey = loadKey(password);
        //initialize cipher
        Cipher Enc = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        byte[] ivBytes = new byte[16];
        //create file input and output streams
        FileInputStream fis = new FileInputStream(fileInput);
        FileOutputStream fos = new FileOutputStream(fileOutput);
        //write iv as the first 16 bytes in the file
        fis.read(ivBytes);
        //create IvParameterSpec
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        //initialize cipher
        Enc.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        //CipherInputStream and CipherOutputStream provide conveient wrappers around standard input and
        //output stream that automatically encrypt and decrypt

        CipherInputStream cis = new CipherInputStream(fis, Enc);
        System.out.println("Encrypting the file ...");
        int theByte = 0;
        while((theByte = cis.read()) != -1)
        {
            //System.out.print(theByte + " ");
            fos.write(theByte);
        }
        fis.close();
        cis.close();
    }
}
