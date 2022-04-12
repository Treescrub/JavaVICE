import java.nio.charset.Charset;
import java.util.Arrays;

public class JavaICE {

    public static byte[] decrypt(String data, int level, byte[] key) {
        return decrypt(data.getBytes(), level, key);
    }

    public static byte[] decrypt(byte[] data, int level, byte[] key) {
        ICEKey iceKey = new ICEKey(level);
        iceKey.set(key);
        return decrypt(data, iceKey);
    }

    public static byte[] decrypt(byte[] data, ICEKey iceKey) {
        byte[] plaintext = new byte[data.length];

        for(int i = 0, bytesLeft = plaintext.length; bytesLeft > 0; i += iceKey.blockSize(), bytesLeft -= iceKey.blockSize()) {
            if(bytesLeft < iceKey.blockSize()) {
                System.arraycopy(data, data.length - bytesLeft, plaintext, i, bytesLeft);
                break;
            }

            byte[] plaintextBlock = new byte[iceKey.blockSize()];
            iceKey.decrypt(Arrays.copyOfRange(data, i, i + iceKey.blockSize()), plaintextBlock);

            System.arraycopy(plaintextBlock, 0, plaintext, i, plaintextBlock.length);
        }

        return plaintext;
    }

    public static byte[] encrypt(String data, int level, byte[] key) {
        return encrypt(data.getBytes(), level, key);
    }

    public static byte[] encrypt(byte[] data, int level, byte[] key) {
        ICEKey iceKey = new ICEKey(level);
        iceKey.set(key);
        return encrypt(data, iceKey);
    }

    public static byte[] encrypt(byte[] data, ICEKey iceKey) {
        byte[] ciphertext = new byte[data.length];

        for(int i = 0, bytesLeft = ciphertext.length; bytesLeft > 0; i += iceKey.blockSize(), bytesLeft -= iceKey.blockSize()) {
            if(bytesLeft < iceKey.blockSize()) {
                System.arraycopy(data, data.length - bytesLeft, ciphertext, i, bytesLeft);
                break;
            }

            byte[] ciphertextBlock = new byte[iceKey.blockSize()];
            iceKey.encrypt(Arrays.copyOfRange(data, i, i + iceKey.blockSize()), ciphertextBlock);

            System.arraycopy(ciphertextBlock, 0, ciphertext, i, ciphertextBlock.length);
        }

        return ciphertext;
    }
}
