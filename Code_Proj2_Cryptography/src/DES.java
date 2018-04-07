import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.generators.DESKeyGenerator;
import org.bouncycastle.crypto.generators.DESedeKeyGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.DESParameters;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

/**
 * DES with Bouncy Castle
 */
public class DES {
    BlockCipher engine = new DESEngine();

    /**
     * Create a DES key
     */
    public void doGenerateKey() {
        byte[] key = generateKey();
        if (key != null) {
            System.out.println("Clave generada:" + new String(Hex.encode(key)));
            Utils.instance().saveFile("deskey", Hex.encode(key));
        }
    }

    /**
     * Manages the encryption of a file using DES and a key stored in another file
     */
    public void doEncrypt() {

        byte[] text = Utils.instance().doSelectFile("Choose a file to encrypt", "txt");
        if (text!=null) {
            // Key to apply
            byte[] key = Utils.instance().doSelectFile("Choose a key",
                    "deskey");
            if (key != null) {
                // We store it in hexadecimal to be readable
                byte[] res = encrypt(Hex.decode(key),text);
                System.out.println("Encrypted text (in hexadecimal):"
                        + new String(Hex.encode(res)));
                Utils.instance().saveFile("encdes", Hex.encode(res));
            }
        } else {
            // Nothing to do
        }

    }
    /**
     * Manages the decryption of a file using DES and a key stored in another file
     */
    public void doDecrypt() {
        // File to decrypt
        byte[] fileContent = Utils.instance().doSelectFile(
                "Choose a file to decrypt", "encdes");
        if (fileContent == null) {
            return;
        }
        // Key to use
        byte[] key = Utils.instance().doSelectFile("Choose a key",
                "deskey");
        if (key != null) {
            // Decrypt a file
            byte[] res = decrypt(Hex.decode(key), Hex.decode(fileContent));
            if (res != null) {
                System.out.println("Cleartext:"
                        + new String(res));
            }
        }

    }

    /**
     * Encrypts with DES
     * @param key key
     * @param ptBytes Text to encrypt
     * @return Encrypted text
     */
    protected byte[] encrypt(byte[] key, byte[] ptBytes) {
        // We create an encryption cipher with Padding with CBC
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
                new CBCBlockCipher(engine));
        // We initialize with the key
        cipher.init(true, new KeyParameter(key));
        // Allocate space for the encrypted text
        byte[] rv = new byte[cipher.getOutputSize(ptBytes.length)];
        // Compute it with DES
        int tam = cipher.processBytes(ptBytes, 0, ptBytes.length, rv, 0);
        try {
            // "flush" of the cipher
            cipher.doFinal(rv, tam);
        } catch (Exception ce) {
            ce.printStackTrace();
            return null;
        }

        return rv;
    }

    /**
     * Decrypts with DES
     * This method could be obviated, as the same encryption method could be used -- DES IS SYMMETRIC!
     * It is kept for clarity fo the student
     * @param key Key
     * @param ptBytes Text to decrypt
     * @return Decrypted text
     */
    public byte[] decrypt(byte[] key, byte[] cipherText) {
        // We create an encryption cipher with Padding with CBC
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
                new CBCBlockCipher(engine));
        // We initialize with the key
        cipher.init(false, new KeyParameter(key));
        // Allocate space for the decrypted text
        byte[] rv = new byte[cipher.getOutputSize(cipherText.length)];
        // Compute it with DES
        int tam = cipher.processBytes(cipherText, 0, cipherText.length, rv, 0);
        try {
            // "flush" of the cipher
            cipher.doFinal(rv, tam);
        } catch (Exception ce) {
            System.out.println("Error while decrypting the file:"+ce.getLocalizedMessage());
            //			ce.printStackTrace();
            return null;
        }

        return rv;
    }

    /**
     * Generate a DES key based on a "secure" random value
     *
     *
     * @return Key generated with the length specified in DESParameters
     */
    public byte[] generateKey() {
        // We use a "secure" random class
        SecureRandom sr = null;
        try {
            sr = new SecureRandom();
            sr.setSeed("UCTresM.".getBytes());
        } catch (Exception e) {
            System.err
                    .println("Error while creating the random value");
            return null;
        }

        // Create DES key with the required length
        KeyGenerationParameters kgp = new KeyGenerationParameters(sr,
                (DESParameters.DES_KEY_LENGTH) * 8);

        DESKeyGenerator kg = new DESKeyGenerator();
        kg.init(kgp);

		/*
		 * Third, and finally, generate the key
		 */
        byte[] key = kg.generateKey();
        return key;

    }
}