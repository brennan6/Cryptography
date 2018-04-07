import org.bouncycastle.crypto.digests.GeneralDigest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.digests.SHA512Digest;

/**
 * Executes different hash functions
 */
public class Hash {

    /**
     * Sets MD5 for processing
     */
    public void doMD5() {
        doDigest(new MD5Digest());
    }

    /**
     * Sets SHA1 for processing
     */
    public void doSHA1() {
        doDigest(new SHA1Digest());
    }

    /**
     * Sets Sha512 for processing
     */
    public void doSHA512() {
        doDigestSpecific(new SHA512Digest());
    }

    /**
     * Manages a digest of a file
     * @param digest
     * @return
     */
    protected byte[] doDigest(GeneralDigest digest) {
        byte[] fileContent = Utils.instance().doSelectFile(
                "Choose a file", "txt");
        if (fileContent != null) {
            byte[] result = digest(digest, fileContent);
            System.out.println("The output is:" + new String(Hex.encode(result)));
            return result;
        }
        return null;
    }

    protected byte[] doDigestSpecific(SHA512Digest digest) {
        byte[] fileContent = Utils.instance().doSelectFile(
                "Choose a file", "txt");
        if (fileContent != null) {
            byte[] result = digestSpecific(digest, fileContent);
            System.out.println("The output is:" + new String(Hex.encode(result)));
            return result;
        }
        return null;
    }


    /**
     * Computes the output of the selected hash function
     * @param digest
     * @param input
     * @return
     */
    public byte[] digest(GeneralDigest digest, byte[] input) {
        digest.update(input, 0, input.length);

        // get the output/ digest size and hash it
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return result;
    }

    public byte[] digestSpecific(SHA512Digest digest, byte[] input) {
        digest.update(input, 0, input.length);

        // get the output/ digest size and hash it
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return result;
    }

}