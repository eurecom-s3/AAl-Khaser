package com.experiments.antianalysisproofsample.checkers.environment;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.util.Log;

import com.experiments.antianalysisproofsample.checkers.tampering.MemoryTamperingDetector;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class HookDetector {
    private static final String TAG = HookDetector.class.getCanonicalName();

    private final Context mContext;

    static {
        System.loadLibrary("hookdetector");
    }

    public HookDetector(Context mContext) {
        this.mContext = mContext;
    }

    // Check installed apps for Xposed and Substrate
    public boolean detectHookInstalledPackageNames() {
        boolean result = false;
        PackageManager packageManager = this.mContext.getPackageManager();
        List<ApplicationInfo> appliacationInfoList =
                packageManager.getInstalledApplications(PackageManager.GET_META_DATA);

        for(ApplicationInfo item : appliacationInfoList ){
            if(item.packageName.equals("de.robv.android.xposed.installer") ||
                    item.packageName.equals("com.saurik.substrate")){
                result = true;
                break;
            }
        }

        Log.d(TAG, "* detectHookInstalledPackageNames: " + result);
        return result;
    }

    // Detect processes in /proc/[pid]/maps
    public boolean detectHookProcessArtifacts() {
        boolean result = false;

        Set<String> libraries = new HashSet<String>();
        String mapsFilename="/proc/" + android.os.Process.myPid() + "/maps";
        try {
            BufferedReader reader = new BufferedReader(new FileReader(mapsFilename));
            String line;
            while((line=reader.readLine()) != null){
                if(line.endsWith(".so") || line.endsWith(".jar")){
                    int n = line.lastIndexOf(" ");
                    libraries.add(line.substring(n+1));
                }
            }
            for(String library : libraries){
                if(library.contains("com.saurik.substrate")) {
                    result = true;
                }
                if(library.contains("XposedBridge.jar")) {
                    result = true;
                }
                if (library.contains("frida-") || library.contains("libfrida")) {
                    result = true;
                }
            }

            reader.close();
        } catch (Exception e) { /*Ignore*/ }

        Log.d(TAG, "* detectHookProcessArtifacts: " + result);
        return result;
    }

    public native boolean customGenuineXposedDetectorNative();

    public native boolean detectXposedHookedMethodNative();
    // TODO: Perform process artifact detection also in native code!

    public boolean isDefaultServerListening() {
        final boolean result = isDefaultServerListeningNative();
        return result;
    }

    private native boolean isDefaultServerListeningNative();

    public boolean isFridaOpenPort() {
        boolean result = isFridaOpenPortNative();
        return result;
    }

    private native boolean isFridaOpenPortNative();

    public native boolean detectFridaThreadNative();

    public native boolean detectFridaNamedPipeNative();

    public native boolean detectInstrumentationFrameworkClasses();

    public boolean isHookDetected() {
        MemoryTamperingDetector memoryTamperingDetector = new MemoryTamperingDetector(this.mContext);

        return detectHookInstalledPackageNames() ||
                detectHookProcessArtifacts() ||

                // xposed and substrate specific controls
                customGenuineXposedDetectorNative() ||
                detectXposedHookedMethodNative() ||
                memoryTamperingDetector.detectHookInStackTrace() ||
                memoryTamperingDetector.detectHookInStackTraceNative() ||

                // frida specific controls
                isDefaultServerListening() ||
                isFridaOpenPort() ||
                detectFridaThreadNative() ||
                detectFridaNamedPipeNative() ||
                memoryTamperingDetector.detectRuntimeMemoryFridaStringNative() ||
                memoryTamperingDetector.detectRuntimeMemory2DiskDifferencesNative() ||

                // specific ART instrumentation framework such as epic, yahfa, whale, ecc..
                detectInstrumentationFrameworkClasses() ||

                // Inline hooking controls
                memoryTamperingDetector.detectInlineHookingNative() ||

                // PLT Hooking
                memoryTamperingDetector.detectPltHookingNative();
    }


}
