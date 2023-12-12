package com.experiments.antianalysisproofsample.checkers.environment;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Debug;
import android.util.Log;

import com.experiments.antianalysisproofsample.checkers.tampering.MemoryTamperingDetector;

import java.lang.reflect.Method;

public class DebuggerDetector {
    private static final String TAG = DebuggerDetector.class.getCanonicalName();

    static {
        System.loadLibrary("debuggerdetector");
    }

    private final Context mContext;

    public DebuggerDetector(Context mContext) {
        this.mContext = mContext;
    }

    private static String getProp(Context ctx, String propName) {
        try {
            ClassLoader cl = ctx.getClassLoader();
            Class<?> klazz = cl.loadClass("android.os.properties");
            Method getProp = klazz.getMethod("get", String.class);
            Object[] params = {propName};
            return (String) getProp.invoke(klazz, params);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public boolean isFlagDebuggable() {
        boolean result = ((this.mContext.getApplicationContext().getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) ||
                "1".equals(getProp(this.mContext, "ro.debuggable"));
        Log.d(TAG, "* isFlagDebuggable : " + result);
        return result;
    }

    public boolean isDebuggerConnected() {
        boolean result = Debug.isDebuggerConnected();
        Log.d(TAG, "* isDebuggerConnected : " + result);
        return result;
    }

    public native void messingJdwpDataStructuresNative();

    public boolean basicTimeCheck(){
        long basicThreashold = 8000000;
        long start = Debug.threadCpuTimeNanos();
        // char[] decr = {0x10, 0x20, 0x30, 0x40, 0x50};
        for(int i = 0; i < 1000000; ++i) {
            /*for (int j = 0; j < decr.length; j++) {
                decr[j] ^= ((i + 0x4) % 0x255);
            }*/
            continue;
        }
        long stop = Debug.threadCpuTimeNanos();

        Log.d(TAG, "basicTimeCheck took : " + (stop - start) + "ns - " +
                "is higher than threashold ( " + basicThreashold + " ) : " + ((stop - start) >= basicThreashold));
        return (stop - start) >= basicThreashold;
    }

    public native boolean detectJavaDebuggerNative();

    public native boolean detectTracerPidNative();

    public native boolean detectDebuggerFromPtraceNative();

    public native boolean detectDebuggerDefaultTcpPortNative();

    public boolean isUnderDebug() {
        MemoryTamperingDetector mtd = new MemoryTamperingDetector(this.mContext);

        boolean result = isFlagDebuggable() || // NOTE: is is true if the apk is built in debug mode
                isDebuggerConnected() ||
                basicTimeCheck() ||
                detectJavaDebuggerNative() || // NOTE: the JWDP task is in if the apk is built in debug mode (app is debuggable)
                detectDebuggerDefaultTcpPortNative() ||

                // native
                detectTracerPidNative() ||
                detectDebuggerFromPtraceNative() ||
                mtd.detectBreakPointNative();


        // avoid debugger -> detach Java debugger!
        // messingJdwpDataStructuresNative();

        return result;
    }

}
