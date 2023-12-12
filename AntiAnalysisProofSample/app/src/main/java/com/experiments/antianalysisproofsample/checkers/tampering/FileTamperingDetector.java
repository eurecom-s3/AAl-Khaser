package com.experiments.antianalysisproofsample.checkers.tampering;

import android.content.Context;

public class FileTamperingDetector {
    private static final String TAG = FileTamperingDetector.class.getCanonicalName();

    static {
        System.loadLibrary("filetamperingdetector");
    }

    private final Context mContext;
    private final String packageName;
    public FileTamperingDetector(Context mContext, String packageName) {
        this.mContext = mContext;
        this.packageName = packageName;
    }

    public native boolean detectOdexTamperingNative(String packageName);

    public boolean isFileTampered() {
        return detectOdexTamperingNative(this.packageName);
    }

}
