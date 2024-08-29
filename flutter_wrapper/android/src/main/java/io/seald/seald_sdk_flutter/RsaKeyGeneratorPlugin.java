package io.seald.seald_sdk_flutter;

import androidx.annotation.NonNull;
import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;

import java.security.KeyPairGenerator;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.Map;
import android.util.Log;

public class RsaKeyGeneratorPlugin implements FlutterPlugin, MethodCallHandler {
    private MethodChannel channel;

    @Override
    public void onAttachedToEngine(@NonNull FlutterPluginBinding binding) {
        channel = new MethodChannel(binding.getBinaryMessenger(), "io.seald.seald_sdk_flutter.native_rsa_key_generator");
        channel.setMethodCallHandler(this);
    }

    @Override
    public void onDetachedFromEngine(@NonNull FlutterPluginBinding binding) {
        channel.setMethodCallHandler(null);
        channel = null;
    }

    @Override
    public void onMethodCall(@NonNull MethodCall call, @NonNull Result result) {
        if (call.method.equals("generateRSAKeys")) {
            int keySize;
            if (call.argument("size") != null) {
                keySize = (int) call.argument("size");
                Log.i("RsaKeyGeneratorPlugin", "Generating keys... Size is " + keySize);
            } else {
                keySize = 4096;
                Log.i("RsaKeyGeneratorPlugin", "Generating keys... No size passed. Defaulting to " + keySize);
            }

            CompletableFuture<String> encryptionKeyFuture = CompletableFuture.supplyAsync(() -> generateRsaKey(keySize));
            CompletableFuture<String> signingKeyFuture = CompletableFuture.supplyAsync(() -> generateRsaKey(keySize));

            CompletableFuture.allOf(encryptionKeyFuture, signingKeyFuture).thenAccept(aVoid -> {
                try {
                    String encryptionKey = encryptionKeyFuture.get();
                    String signingKey = signingKeyFuture.get();
                    result.success(Map.of("encryptionKey", encryptionKey, "signingKey", signingKey, "format", "PKCS8"));
                } catch (InterruptedException | ExecutionException e) {
                    result.error("RSA_KEY_GEN_ERROR", "Failed to generate RSA keys: " + e.getMessage(), null);
                }
            }).exceptionally(e -> {
                result.error("RSA_KEY_GEN_EXCEPTION", "Exception occurred during RSA key generation: " + e.getMessage(), null);
                return null;
            });
        } else {
            result.notImplemented();
        }
    }

    private String generateRsaKey(int size) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(size);
            java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
            String privateKeyBase64 = Base64.getEncoder().encodeToString(privateKeySpec.getEncoded());

            return privateKeyBase64;
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate RSA key", e);
        }
    }
}
