package com.experiments.antianalysisproofsample.models.safetynet;

import android.content.Context;
import android.os.Build;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import com.experiments.antianalysisproofsample.BuildConfig;
import com.experiments.antianalysisproofsample.utils.BooleanHolder;
import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.api.CommonStatusCodes;
import com.google.android.gms.safetynet.SafetyNet;
import com.google.android.gms.safetynet.SafetyNetApi;
import com.google.android.gms.safetynet.SafetyNetClient;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Task;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;

import org.apache.http.conn.ssl.DefaultHostnameVerifier;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.Random;

import javax.net.ssl.SSLException;


// Note: possible contromeasure is to compute the safetynet response from an external device!
// Official doc: https://developer.android.com/training/safetynet/

public class SafetyNetWrapper {
    private static final String TAG = SafetyNetWrapper.class.getCanonicalName();

    private final Random mRandom = new SecureRandom();
    // private boolean
    private final BooleanHolder bh;
    private final String packageName;

    private AttestationStatement stmt;

    public SafetyNetWrapper(Context context, BooleanHolder bh) {
        if (bh == null) {
            throw new IllegalArgumentException();
        }
        this.bh = bh;
        this.packageName = context.getPackageName();
        this.stmt = null;

        // start request to SafefyNet
        this.sendSafetyNetRequest(context);
    }

    public AttestationStatement getStmt() {
        return stmt;
    }

    public BooleanHolder getBh() {
        return bh;
    }

    /**
     * Generates a 16-byte nonce with additional data.
     * The nonce should also include additional information, such as a user id or any other details
     * you wish to bind to this attestation. Here you can provide a String that is included in the
     * nonce after 24 random bytes. During verification, extract this data again and check it
     * against the request that was made with this nonce.
     */
    private byte[] getRequestNonce(String data) {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        byte[] bytes = new byte[24];
        mRandom.nextBytes(bytes);
        try {
            byteStream.write(bytes);
            byteStream.write(data.getBytes());
        } catch (IOException e) {
            return null;
        }

        return byteStream.toByteArray();
    }

    private void sendSafetyNetRequest(Context context) {
        Log.i(TAG, "Sending SafetyNet API request.");

        // TODO(developer): Change the nonce generation to include your own, used once value, ideally from your remote server.
        String nonceData = "Safety Net Sample: " + System.currentTimeMillis();
        byte[] nonce = getRequestNonce(nonceData);

        /*
         Call the SafetyNet API asynchronously.
         The result is returned through the success or failure listeners.
         First, get a SafetyNetClient for the foreground Activity.
         Next, make the call to the attestation API. The API key is specified in the gradle build
         configuration and read from the gradle.properties file.
         */
        SafetyNetClient client = SafetyNet.getClient(context);
        Task<SafetyNetApi.AttestationResponse> task = client.attest(nonce, BuildConfig.API_KEY);

        task.addOnSuccessListener(mSuccessListener)
                .addOnFailureListener(mFailureListener);
    }

    private static final DefaultHostnameVerifier HOSTNAME_VERIFIER = new DefaultHostnameVerifier();

    private static AttestationStatement parseAndVerify(String signedAttestationStatment) {
        // NOTE: I checked in app, but you need to test it on a (secure) remote server

        // Parse JSON Web Signature format.
        JsonWebSignature jws;
        try {
            jws = JsonWebSignature.parser(JacksonFactory.getDefaultInstance())
                    .setPayloadClass(AttestationStatement.class).parse(signedAttestationStatment);
        } catch (IOException e) {
            Log.w(TAG, "Failure: " + signedAttestationStatment + " is not valid JWS " +
                    "format.");
            return null;
        }

        // Verify the signature of the JWS and retrieve the signature certificate.
        X509Certificate cert;
        try {
            cert = jws.verifySignature();
            if (cert == null) {
                Log.w(TAG, "Failure: Signature verification failed.");
                return null;
            }
        } catch (GeneralSecurityException e) {
            Log.w(TAG, 
                    "Failure: Error during cryptographic verification of the JWS signature.");
            return null;
        }

        // Verify the hostname of the certificate.
        if (!verifyHostname("attest.android.com", cert)) {
            Log.w(TAG, "Failure: Certificate isn't issued for the hostname attest.android" +
                    ".com.");
            return null;
        }

        // Extract and use the payload data.
        AttestationStatement stmt = (AttestationStatement) jws.getPayload();
        return stmt;
    }

    /**
     * Verifies that the certificate matches the specified hostname.
     * Uses the {@link DefaultHostnameVerifier} from the Apache HttpClient library
     * to confirm that the hostname matches the certificate.
     *
     * @param hostname
     * @param leafCert
     * @return
     */
    private static boolean verifyHostname(String hostname, X509Certificate leafCert) {
        try {
            // Check that the hostname matches the certificate. This method throws an exception if
            // the cert could not be verified.
            HOSTNAME_VERIFIER.verify(hostname, leafCert);
            return true;
        } catch (SSLException e) {
            e.printStackTrace();
        }

        return false;
    }

    /**
     * Called after successfully communicating with the SafetyNet API.
     * The #onSuccess callback receives an
     * {@link com.google.android.gms.safetynet.SafetyNetApi.AttestationResponse} that contains a
     * JwsResult with the attestation result.
     */
    private OnSuccessListener<SafetyNetApi.AttestationResponse> mSuccessListener =
            new OnSuccessListener<SafetyNetApi.AttestationResponse>() {
                @RequiresApi(api = Build.VERSION_CODES.O)
                @Override
                public void onSuccess(SafetyNetApi.AttestationResponse attestationResponse) {
                    String jwsResult = attestationResponse.getJwsResult();
                    Log.d(TAG, "Success! SafetyNet jws result:\n" + jwsResult + "\n");

                    /*
                     TODO(developer): Forward this result to your server together with
                     the nonce for verification.
                     You can also parse the JwsResult locally to confirm that the API
                     returned a response by checking for an 'error' field first and before
                     retrying the request with an exponential backoff.
                     NOTE: Do NOT rely on a local, client-side only check for security, you
                     must verify the response on a remote server!
                    */

                    // Note: Alternatively use online validation!
                    stmt = parseAndVerify(jwsResult);
                    assert packageName.equals(Objects.requireNonNull(stmt).getApkPackageName());

                    synchronized (bh) {
                        bh.isTaskFinished = true;
                        bh.notifyAll();
                    }
                }
            };

    /**
     * Called when an error occurred when communicating with the SafetyNet API.
     */
    private OnFailureListener mFailureListener =
        new OnFailureListener() {
            @Override
            public void onFailure(@NonNull Exception e) {
                // An error occurred while communicating with the service.
                stmt = null;

                if (e instanceof ApiException) {
                    // An error with the Google Play Services API contains some additional details.
                    ApiException apiException = (ApiException) e;
                    Log.d(TAG, "Error: " +
                            CommonStatusCodes.getStatusCodeString(apiException.getStatusCode()) + ": " +
                            apiException.getStatusMessage());
                } else {
                    // A different, unknown type of error occurred.
                    Log.d(TAG, "ERROR! " + e.getMessage());
                }

                synchronized (bh) {
                    bh.isTaskFinished = true;
                    bh.notifyAll();
                }

            }
        };


}
