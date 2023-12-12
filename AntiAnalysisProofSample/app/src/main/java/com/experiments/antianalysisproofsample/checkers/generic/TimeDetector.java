package com.experiments.antianalysisproofsample.checkers.generic;

import android.content.Context;

import java.util.Calendar;
import java.util.Date;

public class TimeDetector {
    private static final String TAG = TimeDetector.class.getCanonicalName();

    static {
        // import native library
        System.loadLibrary("timedetector");
    }

    private final Context mContext;

    public TimeDetector(Context mContext) {
        this.mContext = mContext;
    }

    public native boolean checkPossibleStrangeUptimeNative();

    public boolean isTimeArtifact() {
        return checkPossibleStrangeUptimeNative();
    }
}
