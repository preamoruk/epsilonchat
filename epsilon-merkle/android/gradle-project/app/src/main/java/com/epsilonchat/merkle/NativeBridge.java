package com.epsilonchat.merkle;

public class NativeBridge {
    static {
        try {
            System.loadLibrary("epsilon");
        } catch (UnsatisfiedLinkError e) {
            // Native library not available — will use WebView fallback
        }
    }

    public static boolean isNativeAvailable() {
        return true; // Would check if lib loaded
    }

    public native String startMesh();
    public native boolean sendMessage(String text, String to);
    public native String getBalance(String wallet);
    public native String generateInvite();
    public native boolean connect(String link);
    public native String getMessages(String chatId);
    public native String requestProof(long leafIndex);
    public native String claimRewards(String receiptsHash, long leafIndex);
}