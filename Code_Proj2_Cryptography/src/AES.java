import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * AES with Bouncy Castle
 *
 */
public class AES {
    // Create an AES engine with 16 bytes
    public final int blockSize = 16;

    /**
     * Creates an AES key and stores it in hexadecimal form
     */
    public void doGenerateKey() {
        byte[] key = generateKeyAndIV();
        if (key != null) {
            System.out.println("Generated Key:"
                    + new String(Hex.encode(Arrays.copyOfRange(key, 0, 24))));
            System.out.println("Generated IV:"
                    + new String(Hex.encode(Arrays.copyOfRange(key, 24,
                    blockSize + 24))));
            Utils.instance().saveFile("aeskeyiv", Hex.encode(key));
        }
    }

    /**
     * Encrypts a txt file using AES key
     */
    public void doEncrypt() {
        byte[] text = Utils.instance().doSelectFile(
                "Choose a file to encrypt", "txt");
        if (text != null) {
            byte[] key = Utils.instance().doSelectFile("Choose a key",
                    "aeskeyiv");
            if (key != null) {
                byte[] res = encrypt(text,
                        Arrays.copyOfRange(Hex.decode(key), 0, 24),
                        Arrays.copyOfRange(Hex.decode(key), 24, 24 + blockSize));
                System.out.println("Encrypted text (in hexadecimal):"
                        + new String(Hex.encode(res)));
                Utils.instance().saveFile("encaes", Hex.encode(res));
            }
        } else {
            // Nothing to do
        }

    }

    /**
     * Decrypts a file using AES key
     */
    public void doDecrypt() {
        byte[] fileContent = Utils.instance().doSelectFile(
                "Choose an encrypted file", "encaes");
        if (fileContent == null) {
            return;
        }
        byte[] key = Utils.instance().doSelectFile("Choose a key",
                "aeskeyiv");
        if (key != null) {
            byte[] res = decrypt(Hex.decode(fileContent),
                    Arrays.copyOfRange(Hex.decode(key), 0, 24),
                    Arrays.copyOfRange(Hex.decode(key), 24, blockSize + 24));
            if (res != null) {
                System.out.println("Texto en claro:" + new String(res));
            }
        }

    }

    /**
     * Encrypt/Decrypt info with AES. As it is a symmetric cipher, it can be used for both encryption and decryption
     *
     * @param cipher
     *            Cifrador/Descifrador AES
     * @param data
     *            Datos origen
     * @return Datos destino
     * @throws Exception
     */
    private static byte[] cipherData(PaddedBufferedBlockCipher cipher,
                                     byte[] data) throws Exception {
        // Create a byte array with the expected size of the output
        int minSize = cipher.getOutputSize(data.length);
        byte[] outBuf = new byte[minSize];
        // Compute all data bytes
        int length1 = cipher.processBytes(data, 0, data.length, outBuf, 0);
        // Final computation (like flushing the streams)
        int length2 = cipher.doFinal(outBuf, length1);
        int actualLength = length1 + length2;
        byte[] result = new byte[actualLength];
        // Copy the result and return it
        System.arraycopy(outBuf, 0, result, 0, result.length);
        return result;
    }

    /**
     * Decrypts with AES. It could be the same method as above, but we duplicate it for clarity for the student
     *
     * @param ciphered
     *            Encrypted data
     * @param key
     *            Key (24 bytes)
     * @param iv
     *            Initialization Vector (Size in bytes of the block)
     * @return Datos descifrados
     */
    private static byte[] decrypt(byte[] ciphered, byte[] key, byte[] iv) {
        try {
            // Create the cipher
            PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(
                    new CBCBlockCipher(new AESEngine()));
            // Prepare key and IV
            CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(
                    key), iv);
            aes.init(false, ivAndKey);
            return cipherData(aes, ciphered);
        } catch (Exception e) {
            System.out
                    .println("Error while decrypting:"
                            + e);
            return null;
        }
    }

    /**
     * Encrypt with AES
     *
     * @param datos
     *            a cifrar
     * @param key
     *            Clave (24 bytes)
     * @param iv
     *            Vector de Inicialización (Tamaño en bytes del bloque)
     * @return Datos cifrados
     */
    private static byte[] encrypt(byte[] plain, byte[] key, byte[] iv) {
        try {
            PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(
                    new CBCBlockCipher(new AESEngine()));
            CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(
                    key), iv);
            aes.init(true, ivAndKey);
            return cipherData(aes, plain);
        } catch (Exception e) {
            System.out
                    .println("Error while encrypting:"
                            + e);
            return null;
        }
    }

    /**
     * Creates Key and IV based on a "secure" random value
     *
     * @return 24+blocksize bytes (Clave+IV)
     */
    public byte[] generateKeyAndIV() {
        // Use the random generator for crypto tasks
        SecureRandom sr = null;
        try {
            sr = new SecureRandom();
            // Use a seed to initialize it
            sr.setSeed("UCTresM.".getBytes());
        } catch (Exception e) {
            System.err
                    .println("Ha ocurrido un error generando el número aleatorio");
            return null;
        }
        // We create it of the desired size (24 bytes de clave + tamaño de bloque como IV)
        byte[] key = sr.generateSeed(24 + blockSize);
        return key;

    }
}