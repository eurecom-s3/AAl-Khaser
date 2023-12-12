package com.experiments.antianalysisproofsample.checkers.tampering;

import android.content.Context;
import android.util.Log;

public class MemoryTamperingDetector {
    private static final String TAG = MemoryTamperingDetector.class.getCanonicalName();

    private final Context mContext;

    static {
        System.loadLibrary("memorytamperingdetector");
    }

    public MemoryTamperingDetector(Context mContext) {
        this.mContext = mContext;
    }

    public boolean detectHookInStackTrace() {
        boolean result = false;

        try {
            throw new Exception("Random exception to verify stack trace");
        } catch (Exception e) {
            int zygoteInitCallCount = 0;
            for (StackTraceElement item : e.getStackTrace()) {
                // Check if "com.android.internal.os.ZygoteInit" occurs twice
                // If yes, it indicates that the Substrate framework has been installed.
                if (item.getClassName().equals("com.android.internal.os.ZygoteInit")) {
                    zygoteInitCallCount++;
                    if (zygoteInitCallCount == 2) {
                        result = true;
                        break;
                    }
                }

                if (item.getClassName().equals("com.saurik.substrate.MS$2") && item.getMethodName().equals("invoke")) {
                    // Substrate
                    result = true;
                    break;
                }

                if (item.getClassName().equals("de.robv.android.xposed.XposedBridge")
                        && item.getMethodName().equals("main")) {
                    // Xposed on the device
                    result = true;
                    break;
                }

                if (item.getClassName().equals("de.robv.android.xposed.XposedBridge")
                        && item.getMethodName().equals("handleHookedMethod")) {
                    // Hooked method by Xposed
                    result = true;
                    break;
                }

                if (item.getClassName().equals("de.robv.android.xposed.XC_MethodHook")) {
                    result = true;
                    break;
                }

            }
        }

        Log.d(TAG, "* detectHookInStackTrace: " + result);
        return result;
    }

    public native boolean detectHookInStackTraceNative();

    public native boolean detectRuntimeMemory2DiskDifferencesNative();

    public native boolean detectRuntimeMemoryFridaStringNative();

    public native boolean detectPltHookingNative();

    public native boolean detectInlineHookingNative();

    public native boolean detectBreakPointNative();

    public boolean isMemoryTampered() {
        return detectHookInStackTrace() ||
                detectHookInStackTraceNative() ||
                detectRuntimeMemory2DiskDifferencesNative() ||
                detectRuntimeMemoryFridaStringNative() ||
                detectPltHookingNative() ||
                detectInlineHookingNative() ||
                detectBreakPointNative();
    }

}
