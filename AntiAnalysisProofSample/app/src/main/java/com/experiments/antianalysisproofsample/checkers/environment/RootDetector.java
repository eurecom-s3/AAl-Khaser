package com.experiments.antianalysisproofsample.checkers.environment;

import android.app.ActivityManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Scanner;

public class RootDetector {
    private static final String TAG = RootDetector.class.getCanonicalName();

    public static final String BINARY_SU = "su";
    public static final String BINARY_BUSYBOX = "busybox";
    public static final String BINARY_MAGISK = "magisk";

    public static final String[] ROOT_APP_PACKAGES = {
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.topjohnwu.magisk",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.smedialink.oneclickroot",
            "com.zhiqupk.root.global",
            "com.alephzain.framaroot",
            "eu.chainfire.supersu",
            "com.noshufou.android.su",
            "com.koushikdutta.superuser",
            "com.zachspong.temprootremovejb",
            "com.ramdroid.appquarantine",
            "com.topjohnwu.magisk"
    };

    public static final String[] CLOAKING_APP_PACKAGES = {
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer",
            "com.saurik.substrate",
            "com.zachspong.temprootremovejb",
            "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree",
            "com.formyhm.hiderootPremium",
            "com.formyhm.hideroot"
    };

    public static final String[] DANGEROUS_APP_PACKAGES = {
            "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license",
            "com.dimonvideo.luckypatcher",
            "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine",
            "com.ramdroid.appquarantinepro",
            "com.android.vending.billing.InAppBillingService.COIN",
            "com.android.vending.billing.InAppBillingService.LUCK",
            "com.chelpus.luckypatcher",
            "com.blackmartalpha",
            "org.blackmart.market",
            "com.allinone.free",
            "com.repodroid.app",
            "org.creeplays.hack",
            "com.baseappfull.fwd",
            "com.zmapp",
            "com.dv.marketmod.installer",
            "org.mobilism.android",
            "com.android.wp.net.log",
            "com.android.camera.update",
            "cc.madkite.freedom",
            "com.solohsu.android.edxp.manager",
            "org.meowcat.edxposed.manager",
            "com.xmodgame",
            "com.cih.game_cih",
            "com.charles.lpoqasert",
            "catch_.me_.if_.you_.can_"
    };

    public static final String[] BINARY_PATHS = {
            "/data/local/",
            "/data/local/bin/",
            "/data/local/xbin/",
            "/sbin/",
            "/su/bin/",
            "/system/bin/",
            "/system/bin/.ext/",
            "/system/bin/failsafe/",
            "/system/sd/xbin/",
            "/system/usr/we-need-root/",
            "/system/xbin/",
            "/cache/",
            "/data/",
            "/dev/"
    };

    public static final String[] READ_ONLY_PATHS = {
            "/system",
            "/system/bin",
            "/system/sbin",
            "/system/xbin",
            "/vendor/bin",
            "/sbin",
            "/etc",
    };

    private final Context mContext;

    static {
        System.loadLibrary("rootdetector");
    }

    public RootDetector(Context mContext) {
        this.mContext = mContext;
    }

    // TODO: Check process name -> e.g., tempName.contains("supersu") || tempName.contains("superuser")

    // Java methods
    public boolean isRooted() {
        return detectRootApps() ||
                detectPotentiallyDangerousApps() ||
                // detectRootCloakingApps() ||
                checkSuExists() ||
                checkForBinary(BINARY_SU) ||
                checkForBinary(BINARY_BUSYBOX) ||
                checkForBinary(BINARY_MAGISK) ||
                checkForProps() ||
                checkForRWPaths() ||
                checkTestKeys() ||
                checkSuExistsNative() ||
                checkForBinaryNative(BINARY_SU) ||
                checkForBinaryNative(BINARY_BUSYBOX) ||
                checkForBinaryNative(BINARY_MAGISK) ||
                checkForPropsNative() ||
                checkForRWPathsNative() ||
                checkTestKeysNative();
    }

    public boolean detectRootApps() {
        ArrayList<String> packages = new ArrayList<>(Arrays.asList(ROOT_APP_PACKAGES));

        boolean result = isAnyPackageFromListInstalled(packages);
        Log.d(TAG, "* detectRootApps: " + result);
        return result;
    }

    public boolean detectPotentiallyDangerousApps() {
        ArrayList<String> packages = new ArrayList<>(Arrays.asList(DANGEROUS_APP_PACKAGES));

        boolean result = isAnyPackageFromListInstalled(packages);
        Log.d(TAG, "* detectPotentiallyDangerousApps: " + result);
        return result;
    }

    public boolean detectRootCloakingApps() {
        boolean result = isAnyPackageFromListInstalled(new ArrayList<>(Arrays.asList(CLOAKING_APP_PACKAGES))) ||
                canLoadNativeLibrary();
        Log.d(TAG, "* detectRootCloakingApps: " + result);
        return result;
    }

    protected boolean canLoadNativeLibrary() {
        try {
            System.loadLibrary("rootdetector");
            // TODO: Check also if we can invoke native libraries
            return true;
        } catch (UnsatisfiedLinkError e) {
            return false;
        }
    }

    protected boolean isAnyPackageFromListInstalled(List<String> packages){
        boolean result = false;

        PackageManager pm = this.mContext.getPackageManager();

        for (String packageName : packages) {
            try {
                // Root app detected
                pm.getPackageInfo(packageName, 0);
                Log.d(TAG, "Suspicious app package \"" + packageName + "\" detected!");
                result = true;
            } catch (PackageManager.NameNotFoundException e) {
                // Exception thrown, package is not installed into the system
            }
        }

        return result;
    }

    public boolean checkForBinary(String filename) {
        boolean result = false;

        for (String path : BINARY_PATHS) {
            File f = new File(path, filename);
            boolean fileExists = f.exists();
            if (fileExists) {
                Log.d(TAG, "Binary " + filename + " found in  " + f.getAbsolutePath());
                result = true;
            }
        }

        Log.d(TAG, "* checkForBinary: " + result);
        return result;
    }

    public boolean checkForProps() {
        final Map<String, String> dangerousProps = new HashMap<>();
        dangerousProps.put("ro.debuggable", "1");
        dangerousProps.put("ro.secure", "0");
        dangerousProps.put("sys.initd", "1");
        dangerousProps.put("service.adb.root", "1");
        dangerousProps.put("ro.build.selinux", "0");

        boolean result = false;
        String[] lines = runCommand("getprop");

        if (lines == null){
            // Could not read, assume false;
            return false;
        }

        for (String line : lines) {
            for (String key : dangerousProps.keySet()) {
                if (line.contains(key)) {
                    String badValue = dangerousProps.get(key);
                    badValue = "[" + badValue + "]";
                    if (line.contains(badValue)) {
                        Log.d(TAG, "Prop " + key + " = " + badValue + " detected!");
                        result = true;
                    }
                }
            }
        }

        Log.d(TAG, "* checkForProps: " + result);
        return result;
    }

    public boolean checkForRWPaths() {
        boolean result = false;
        int sdkVersion = android.os.Build.VERSION.SDK_INT;

        //Run the command "mount" to retrieve all mounted directories
        String[] lines = runCommand("mount");

        if (lines == null){
            // Could not read, assume false;
            return false;
        }

        for (String line : lines) {
            // Split lines into parts
            String[] args = line.split(" ");

            if ((sdkVersion <= android.os.Build.VERSION_CODES.M && args.length < 4)
                    || (sdkVersion > android.os.Build.VERSION_CODES.M && args.length < 6)) {
                // If we don't have enough options per line, skip this and log an error
                Log.e(TAG, "Error formatting mount line: "+line);
                continue;
            }

            String mountPoint;
            String mountOptions;

            if (sdkVersion > android.os.Build.VERSION_CODES.M) {
                mountPoint = args[2];
                mountOptions = args[5];
            } else {
                mountPoint = args[1];
                mountOptions = args[3];
            }

            for(String pathToCheck: READ_ONLY_PATHS) {
                if (mountPoint.equalsIgnoreCase(pathToCheck)) {

                    /*
                     * If the device is running an Android version above Marshmallow,
                     * need to remove parentheses from options parameter;
                     */
                    if (android.os.Build.VERSION.SDK_INT > android.os.Build.VERSION_CODES.M) {
                        mountOptions = mountOptions.replace("(", "");
                        mountOptions = mountOptions.replace(")", "");

                    }

                    // Split options out and compare against "rw" to avoid false positives
                    for (String option : mountOptions.split(",")){

                        if (option.equalsIgnoreCase("rw")){
                            Log.d(TAG, "Detected \"" + pathToCheck + "\n mounted with rw permissions!");
                            result = true;
                            break;
                        }
                    }
                }
            }
        }

        Log.d(TAG, "* checkForProps: " + result);
        return result;
    }

    protected String[] runCommand(String cmd) {
        try {
            InputStream inputstream = Runtime.getRuntime().exec(cmd).getInputStream();
            if (inputstream == null) return null;
            String propVal = new Scanner(inputstream).useDelimiter("\\A").next();
            return propVal.split("\n");
        } catch (IOException | NoSuchElementException e) {
            Log.e(TAG, "Error on command: \"" + cmd + "\". Message: " + e.toString());
            return null;
        }
    }

    public boolean checkTestKeys() {
        String buildTags = android.os.Build.TAGS;
        boolean result = buildTags != null &&
                (buildTags.contains("test-keys") || buildTags.contains("dev-keys") || !buildTags.contains("release-keys"));
        Log.d(TAG, "* checkTestKeys: " + result);
        return result;
    }

    public boolean checkSuExists() {
        Process process = null;
        boolean result;
        try {
            process = Runtime.getRuntime().exec(new String[] { "which", BINARY_SU });
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            result = in.readLine() != null;
        } catch (Throwable t) {
            result = false;
        } finally {
            if (process != null) process.destroy();
        }

        Log.d(TAG, "* checkSuExists: " + result);
        return result;
    }

    // Native methods
    public native boolean checkSuExistsNative();

    public native boolean checkForBinaryNative(String filename);

    public native boolean checkForPropsNative();

    public native boolean checkForRWPathsNative();

    public native boolean checkTestKeysNative();

}
