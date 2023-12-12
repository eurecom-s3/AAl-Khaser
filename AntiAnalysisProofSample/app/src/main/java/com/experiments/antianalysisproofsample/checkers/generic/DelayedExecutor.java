package com.experiments.antianalysisproofsample.checkers.generic;

import android.annotation.SuppressLint;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Debug;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.util.Log;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Calendar;
import java.util.Date;

public class DelayedExecutor {
    private static final String TAG = DelayedExecutor.class.getCanonicalName();

    private static final String SERVER_HOSTNAME = "8.8.8.8"; // fake.hostname
    private static final int SERVER_PORT = 80;
    private static final Date TARGET_DATE;

    static {
        Calendar.getInstance().clear();
        Calendar.getInstance().set(2022, 1, 10);
        TARGET_DATE = Calendar.getInstance().getTime();
        Calendar.getInstance().clear();

        // import native library
        System.loadLibrary("delayedexecutor");
    }

    private final Context mContext;

    public DelayedExecutor(Context mContext) {
        this.mContext = mContext;
    }

    @SuppressLint({"HardwareIds", "MissingPermission"})
    private void maliciousCode() {
        TelephonyManager telephonyManager = (TelephonyManager) this.mContext.getSystemService(Context.TELEPHONY_SERVICE);
        String imei = null;
        try {
             imei = telephonyManager.getDeviceId();
        } catch (Exception e) {
            // alternatively I can use
            imei = Settings.Secure.getString(this.mContext.getContentResolver(), Settings.Secure.ANDROID_ID);
        }
        Log.d(TAG, "Malicious code running!1!!\n -> Devide IMEI is : " + imei);
    }

    /*private boolean runMaliciousAfterSleep(int timeout) {
        long start = Debug.threadCpuTimeNanos();
        try {
            Thread.sleep(timeout);
        } catch (Exception e) {
            Log.e(TAG, "Exception occurred in sleep. Error = " + e.toString());
        } finally {
            Log.d(TAG, "Sleep ended --> Check how much sleeping");
            long end = Debug.threadCpuTimeNanos();
            if ((end - start) > (timeout*1000)) {
                Log.d(TAG, "Running malicious code");
                maliciousCode();
                return true;
            } else {
                Log.d(TAG, "Something went wrong: I do not sleep enougth");
            }
        }
        return false;
    }

    public boolean runMaliciousAfterSocketTimeout(int timeout) {
        InetSocketAddress sockAdr = new InetSocketAddress(SERVER_HOSTNAME, SERVER_PORT);
        Socket socket = new Socket();
        long start = Debug.threadCpuTimeNanos();
        try {
            socket.connect(sockAdr, timeout*1000);
        } catch (SocketTimeoutException e) {
            Log.d(TAG, "Timeout expired --> Check how much sleeping");
            long end = Debug.threadCpuTimeNanos();
            if ((end - start) > (timeout*1000000)) { // TODO: Check this --> Do I need an hard-coded value?
                Log.d(TAG, "Running malicious code");
                maliciousCode();
                return true;
            } else {
                Log.d(TAG, "Something went wrong: I do not wait enougth");
            }
        } catch (Exception e) {
            Log.e(TAG, "Exception occurred in socket. Error = " + e.toString());
        } finally {
            try {
                socket.close();
            } catch (IOException e) { }
        }
        return false;
    }

    public native boolean runMaliciousAfterSocketTimeoutNative(int timeout);

    public boolean runMaliciousAfterSpecificDate() {
        Date currentTime = Calendar.getInstance().getTime();
        if (currentTime.after(TARGET_DATE)) {
            Log.d(TAG, "Date after target date -> Run malicious code");
            maliciousCode();
            return true;
        }

        return false;
    }*/

    public static class BootCompletedReceiver extends BroadcastReceiver {
        private static final String TAG = BootCompletedReceiver.class.getCanonicalName();
        public static boolean isBootDetected = false;

        @Override
        public void onReceive(Context context, Intent intent) {
            isBootDetected = true;
            Log.d(TAG, "Received boot completed (possible reboot) -> Run malicious code");
            (new DelayedExecutor(context)).maliciousCode();
        }
    }

}
