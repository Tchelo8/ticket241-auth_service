package com.tchelo.auth_service.service.impl;

import com.tchelo.auth_service.service.TotpService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

@Slf4j
@Service
public class TotpServiceImpl implements TotpService {

    private static final String ISSUER = "Ticket241";
    private static final int TIME_STEP = 30;
    private static final int DIGITS = 6;
    private static final String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    @Override
    public String generateSecret() {
        byte[] bytes = new byte[20];
        new SecureRandom().nextBytes(bytes);
        return base32Encode(bytes);
    }

    @Override
    public String buildOtpAuthUri(String secret, String phone) {
        String label = encode(ISSUER + ":" + phone);
        String issuer = encode(ISSUER);
        return "otpauth://totp/" + label
                + "?secret=" + secret
                + "&issuer=" + issuer
                + "&algorithm=SHA1"
                + "&digits=" + DIGITS
                + "&period=" + TIME_STEP;
    }

    @Override
    public boolean verifyCode(String secret, String code) {
        try {
            byte[] keyBytes = base32Decode(secret);
            long timeStep = System.currentTimeMillis() / 1000 / TIME_STEP;
            // Fenêtre de ±1 pour tolérer un léger décalage d'horloge
            for (int delta = -1; delta <= 1; delta++) {
                if (generateTotp(keyBytes, timeStep + delta).equals(code)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            log.warn("Échec de vérification TOTP : {}", e.getMessage());
            return false;
        }
    }

    // ── TOTP / RFC 6238 ──────────────────────────────────────────────────────

    private String generateTotp(byte[] key, long counter) throws Exception {
        byte[] msg = ByteBuffer.allocate(8).putLong(counter).array();
        byte[] hash = hmacSha1(key, msg);
        int offset = hash[hash.length - 1] & 0x0F;
        int binary = ((hash[offset]     & 0x7F) << 24)
                   | ((hash[offset + 1] & 0xFF) << 16)
                   | ((hash[offset + 2] & 0xFF) << 8)
                   |  (hash[offset + 3] & 0xFF);
        return String.format("%0" + DIGITS + "d", binary % 1_000_000);
    }

    private byte[] hmacSha1(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(key, "HmacSHA1"));
        return mac.doFinal(data);
    }

    // ── Base32 (RFC 4648) ────────────────────────────────────────────────────

    private String base32Encode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int buffer = 0, bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                bitsLeft -= 5;
                sb.append(BASE32_CHARS.charAt((buffer >> bitsLeft) & 0x1F));
            }
        }
        if (bitsLeft > 0) {
            sb.append(BASE32_CHARS.charAt((buffer << (5 - bitsLeft)) & 0x1F));
        }
        return sb.toString();
    }

    private byte[] base32Decode(String input) {
        input = input.toUpperCase().replaceAll("[=\\s]", "");
        byte[] output = new byte[input.length() * 5 / 8];
        int buffer = 0, bitsLeft = 0, idx = 0;
        for (char c : input.toCharArray()) {
            int val = BASE32_CHARS.indexOf(c);
            if (val < 0) continue;
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                output[idx++] = (byte) ((buffer >> bitsLeft) & 0xFF);
            }
        }
        return output;
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
