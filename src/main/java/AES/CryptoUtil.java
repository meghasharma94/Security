import java.security.GeneralSecurityException;

public class CryptoUtil {

    private static final String KEY="LetDoSomeEncrypt";

    public static String encrypt(String plainText, AESCrypto aes) throws GeneralSecurityException {
        return aes.encrypt(plainText);
     }

    public static String decrypt(String cipherText, AESCrypto aes) throws GeneralSecurityException {
        return aes.decrypt(cipherText);
    }

    public static void main(String[] args) throws GeneralSecurityException {
        AESCrypto aes = new AESCrypto(KEY);
        String plainText="TimeToDoSomeFunWork";
        String cipherText=encrypt(plainText, aes);
        String text=decrypt(cipherText, aes);

        System.out.println("Plain text "+ plainText);

        System.out.println("Encrypted Text "+ cipherText);
        System.out.println("Decrypted Text "+ text);

        System.out.println("Are plainText and text after decryption same "+ plainText.equals(text));
    }
}
