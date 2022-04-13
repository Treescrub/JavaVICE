public class Key {
    public static final int THIN_ICE = 0;
    public static final int ICE = 1;
    public static final int ICE_2 = 2;

    private ICEKey iceKey;

    public Key(ICEKey iceKey) {
        this.iceKey = iceKey;
    }

    public Key(byte[] keyBytes, int level) {
        iceKey = new ICEKey(level);
        iceKey.set(keyBytes);
    }

    public Key(String keyString, int level) {
        this(keyString.getBytes(), level);
    }

    public int getBlockSize() {
        return iceKey.blockSize();
    }

    public byte[] decryptBlock(byte[] block) {
        byte[] plaintextBlock = new byte[getBlockSize()];
        iceKey.decrypt(block, plaintextBlock);
        return plaintextBlock;
    }

    public byte[] encryptBlock(byte[] block) {
        byte[] ciphertextBlock = new byte[getBlockSize()];
        iceKey.encrypt(block, ciphertextBlock);
        return ciphertextBlock;
    }
}
