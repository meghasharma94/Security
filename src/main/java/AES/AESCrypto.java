import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;


public class AESCrypto {

    private static final String ENCRYPT_ALGO_GCM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_SIZE_BITS = 128;
    private static final int GCM_IV_SIZE_BYTES = 12;
    private byte[] aesKey;
    private SecretKey secretKey;
    private static byte[] iv;
    private Cipher cipher;

    public AESCrypto(String key) {
        try {
            aesKey = key.getBytes(StandardCharsets.UTF_8);
            secretKey = new SecretKeySpec(aesKey, "AES");
            cipher = Cipher.getInstance(ENCRYPT_ALGO_GCM);
            iv=generateRandomIV();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    public String decrypt(String cipherMessage) throws GeneralSecurityException {

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO_GCM);
        byte[] ivAndCTwithTag = unHex(cipherMessage);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_SIZE_BITS, ivAndCTwithTag, 0, GCM_IV_SIZE_BYTES);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        byte[] plainText = cipher.doFinal(ivAndCTwithTag, GCM_IV_SIZE_BYTES, ivAndCTwithTag.length - GCM_IV_SIZE_BYTES);

        return new String(plainText, StandardCharsets.UTF_8);
    }


    public String encrypt(String plainText) throws GeneralSecurityException {

        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_SIZE_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        byte[] byteText = plainText.getBytes(StandardCharsets.UTF_8);

        byte[] ivCTAndTag = new byte[GCM_IV_SIZE_BYTES + cipher.getOutputSize(byteText.length)];
        System.arraycopy(iv, 0, ivCTAndTag, 0, GCM_IV_SIZE_BYTES);
        cipher.doFinal(byteText, 0, byteText.length, ivCTAndTag, GCM_IV_SIZE_BYTES);

        return hex(ivCTAndTag);
    }


    private static byte[] unHex(String hex) {
        try {
            return Hex.decodeHex(hex);
        } catch (DecoderException e) {
            throw new IllegalArgumentException("Invalid Hex format!");
        }
    }

    private static String hex(byte[] cipherText) {
        return new String(Hex.encodeHex(cipherText));
    }

    private static byte[] generateRandomIV() {
        byte[] iv = new byte[GCM_IV_SIZE_BYTES];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        return iv;
    }
}
