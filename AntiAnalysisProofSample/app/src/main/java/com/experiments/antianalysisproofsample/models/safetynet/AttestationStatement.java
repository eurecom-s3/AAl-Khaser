package com.experiments.antianalysisproofsample.models.safetynet;


import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.util.Base64;
import com.google.api.client.util.Key;

/**
 * A statement returned by the Attestation API.
 */
public class AttestationStatement extends JsonWebSignature.Payload {
    /**
     * Embedded nonce sent as part of the request.
     */
    @Key
    private String nonce;

    /**
     * Timestamp of the request.
     */
    @Key
    private long timestampMs;

    /**
     * Package name of the APK that submitted this request.
     */
    @Key
    private String apkPackageName;

    /**
     * Digest of certificate of the APK that submitted this request.
     */
    @Key
    private String[] apkCertificateDigestSha256;

    /**
     * Digest of the APK that submitted this request.
     */
    @Key
    private String apkDigestSha256;

    /**
     * The device passed CTS and matches a known profile.
     */
    @Key
    private boolean ctsProfileMatch;

    /**
     * The device has passed a basic integrity test, but the CTS profile could not be verified.
     */
    @Key
    private boolean basicIntegrity;

    /**
     * Types of measurements that contributed to this response.
     */
    @Key
    private String evaluationType;

    public byte[] getNonce() {
        return Base64.decodeBase64(nonce);
    }

    public long getTimestampMs() {
        return timestampMs;
    }

    public String getApkPackageName() {
        return apkPackageName;
    }

    public byte[] getApkDigestSha256() {
        return Base64.decodeBase64(apkDigestSha256);
    }

    public byte[][] getApkCertificateDigestSha256() {
        byte[][] certs = new byte[apkCertificateDigestSha256.length][];
        for (int i = 0; i < apkCertificateDigestSha256.length; i++) {
            certs[i] = Base64.decodeBase64(apkCertificateDigestSha256[i]);
        }
        return certs;
    }

    public boolean isCtsProfileMatch() {
        return ctsProfileMatch;
    }

    public boolean hasBasicIntegrity() {
        return basicIntegrity;
    }

    public boolean hasBasicEvaluationType() {
        return evaluationType.contains("BASIC");
    }

    public boolean hasHardwareBackedEvaluationType() {
        return evaluationType.contains("HARDWARE_BACKED");
    }
}