import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedList;
import java.util.Queue;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESEncryption {
    private static final String ALGORITHM = "AES/GCM/NoPadding";

    public static void main(String[] args) {
        try {
            String filePath = "sample.txt";
            String key = "YourBase64EncodedAESKey"; // Replace with your actual AES key in Base64 format

            encryptFile(filePath, key);
            decryptFile(filePath + ".enc", key);
            System.out.println("File encryption and decryption completed successfully.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void encryptFile(String filePath, String key) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            // Generate the cipher object.
            Cipher cipher = Cipher.getInstance(ALGORITHM);

            // Generate the encryption key.
            byte[] keyBytes = Base64.getDecoder().decode(key);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            // Get the initialization vector (IV).
            byte[] iv = cipher.getIV();

            // Create the input and output queues.
            Queue<Byte> inputQueue = new LinkedList<>();
            Queue<Byte> outputQueue = new LinkedList<>();

            // Read the file contents into the input queue.
            FileInputStream fis = new FileInputStream(filePath);
            int length;
            while ((length = fis.read()) != -1) {
                inputQueue.offer((byte) length);
            }
            fis.close();

            // Encrypt the file contents and write the ciphertext to the output queue.
            byte[] input = new byte[1];
            length = inputQueue.poll();
            while (length >0) {
                input[0] = (byte) length;
                byte[] output = cipher.update(input, 0, 1);
                for (byte b : output) {
                    outputQueue.offer(b);
                }
            }
            byte[] output = cipher.doFinal();
            for (byte b : output) {
                outputQueue.offer(b);
            }

            // Write the IV and ciphertext to the output file.
            FileOutputStream fos = new FileOutputStream(filePath + ".enc");
            fos.write(iv);
            while ((length = outputQueue.poll()) >0) {
                fos.write(length);
            }
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void decryptFile(String filePath, String key) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            // Generate the cipher object.
            Cipher cipher = Cipher.getInstance(ALGORITHM);

            // Generate the decryption key.
            byte[] keyBytes = Base64.getDecoder().decode(key);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

            FileInputStream fis = new FileInputStream(filePath);
            byte[] iv = new byte[12];
            fis.read(iv);

            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));

            // Create the input and output queues.
            Queue<Byte> inputQueue = new LinkedList<>();
            Queue<Byte> outputQueue = new LinkedList<>();

            // Read the IV and ciphertext from the input file into the input queue.
            int length;
            for (byte b : iv) {
                inputQueue.offer(b);
            }
            while ((length = fis.read()) != -1) {
                inputQueue.offer((byte) length);
            }
            fis.close();

            // Decrypt the file contents and write the plaintext to the output queue.
            byte[] input = new byte[1];
            length = inputQueue.poll();
            while (length>0)
            {
                input[0] = (byte) length;
                byte[] output = cipher.update(input, 0, 1);
                for (byte b : output) {
                    outputQueue.offer(b);
                }
            }
            byte[] output = cipher.doFinal();
            for (byte b : output) {
                outputQueue.offer(b);
            }

            // Write the plaintext to the output file.
            FileOutputStream fos = new FileOutputStream("decrypted.txt");
            while ((length = outputQueue.poll()) >0) {
                fos.write(length);
            }
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
