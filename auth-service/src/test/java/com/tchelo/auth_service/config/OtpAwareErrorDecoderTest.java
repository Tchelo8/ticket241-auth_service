package com.tchelo.auth_service.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tchelo.auth_service.client.OtpInvalidCodeException;
import feign.FeignException;
import feign.Request;
import feign.Response;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class OtpAwareErrorDecoderTest {

    // Même réglage que l'ObjectMapper Spring : les champs inconnus sont ignorés
    private final OtpAwareErrorDecoder decoder = new OtpAwareErrorDecoder(
            new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false));

    private Response response(int status, String body) {
        Request request = Request.create(Request.HttpMethod.POST, "http://notification/api/notifications/otp/verify",
                Map.of(), null, StandardCharsets.UTF_8, null);
        return Response.builder()
                .status(status)
                .reason("test")
                .request(request)
                .headers(Map.of())
                .body(body, StandardCharsets.UTF_8)
                .build();
    }

    @Test
    void otpRejectionIsTreatedAsInvalidCode() {
        Exception e = decoder.decode("verifyOtp",
                response(401, "{\"valid\":false,\"message\":\"Code OTP incorrect\",\"remainingAttempts\":4}"));

        assertThat(e).isInstanceOf(OtpInvalidCodeException.class);
        assertThat(((OtpInvalidCodeException) e).getResponse().getRemainingAttempts()).isEqualTo(4);
    }

    @Test
    void rejectedInternalKeyIsATechnicalError() {
        Exception e = decoder.decode("verifyOtp",
                response(403, "{\"status\":403,\"error\":\"INTERNAL_API_KEY_REJECTED\"}"));

        assertThat(e).isInstanceOf(FeignException.class).isNotInstanceOf(OtpInvalidCodeException.class);
    }

    @Test
    void unexpected401WithoutOtpPayloadIsATechnicalError() {
        Exception e = decoder.decode("verifyOtp",
                response(401, "{\"timestamp\":\"2026-10-14\",\"status\":401,\"error\":\"Unauthorized\"}"));

        assertThat(e).isInstanceOf(FeignException.class);
        assertThat(((FeignException) e).contentUTF8()).contains("Unauthorized");
    }
}
