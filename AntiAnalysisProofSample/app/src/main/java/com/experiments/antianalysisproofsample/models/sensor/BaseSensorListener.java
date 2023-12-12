package com.experiments.antianalysisproofsample.models.sensor;

import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.util.Log;

import com.experiments.antianalysisproofsample.utils.BooleanHolder;

import java.util.Arrays;

public abstract class BaseSensorListener implements SensorEventListener {
    private static final String TAG = BaseSensorListener.class.getCanonicalName();

    protected static final double DEFAULT_INAPPROPRIATE_PERCENT = 0.5D;
    protected static final int DEFAULT_D_COUNT_IN_PAIR = 2;

    protected final Context mContext;
    // protected final int sensorType;
    protected int eventCount;
    protected final int steps;
    protected final float[][] sensorData;
    protected final BooleanHolder syncObject;
    protected boolean isEmulator;

    public BaseSensorListener(Context mContext, int sensorType, int steps, BooleanHolder syncObject) {
        this.mContext = mContext;
        // this.sensorType = sensorType;
        this.steps = steps;
        this.eventCount = 0;
        this.sensorData = new float[steps][];
        this.syncObject = syncObject;

        // Register listener
        SensorManager sensorManager = this.mContext.getSystemService(SensorManager.class);
        Sensor sensor = sensorManager.getDefaultSensor(sensorType);
        boolean isRegistered = sensorManager.registerListener(this, sensor, SensorManager.SENSOR_DELAY_UI);

        // Log.d(TAG, "Sensor " + ((Sensor.TYPE_ACCELEROMETER == sensorType) ? "accelerometer" : "gyroscope") +
        //         " registerListener result : " + isRegistered);

        if (!isRegistered) {
            synchronized (syncObject) {
                this.isEmulator = true; // because register fails, which means that there is no valid register
                syncObject.isTaskFinished = true;
                syncObject.notify();
            }
        }
    }

    @Override
    public void onSensorChanged(SensorEvent sensorEvent) {
        float[] lastSensorValues = sensorEvent.values;

        if (eventCount < steps) {
            sensorData[eventCount] = copy(lastSensorValues);
            Log.i(TAG, Arrays.deepToString(sensorData));
            eventCount++;
        }

        if (eventCount >= steps) {
            synchronized (syncObject) {
                if (!syncObject.isTaskFinished) {
                    // unregister listener
                    SensorManager sensorManager = this.mContext.getSystemService(SensorManager.class);
                    sensorManager.unregisterListener(this);

                    // compute if it is emulator
                    checkEmulator();

                    // notify main thread
                    syncObject.isTaskFinished = true;
                    syncObject.notify();
                }
            }
        }
    }

    @Override
    public void onAccuracyChanged(Sensor sensor, int i) {
        // ignore
    }

    private float[] copy(float[] array) {
        float[] copy = new float[array.length];
        System.arraycopy(array, 0, copy, 0, array.length);
        return copy;
    }

    // NOTE: You should implements several different heuristics.
    // This is only a basic example
    private void checkEmulator() {
        float dx, dy, dz;
        float lastX = 0, lastY = 0, lastZ = 0;
        int sameEventCount = 0;

        Log.i(TAG, Arrays.deepToString(sensorData));

        for (int i = 0; i < sensorData.length; i++) {
            if (i == 0) {
                lastX = sensorData[i][0];
                lastY = sensorData[i][1];
                lastZ = sensorData[i][2];
                continue;
            }
            dx = sensorData[i][0] - lastX;
            dy = sensorData[i][1] - lastY;
            dz = sensorData[i][2] - lastZ;
            int sameD = 0;
            if (dx == 0)
                sameD++;
            if (dy == 0)
                sameD++;
            if (dz == 0)
                sameD++;
            if (sameD >= DEFAULT_D_COUNT_IN_PAIR)
                sameEventCount++;
        }
        this.isEmulator =  ((double) sameEventCount / (double) sensorData.length) >= DEFAULT_INAPPROPRIATE_PERCENT;
    }

    public boolean isEmulator() {
        synchronized (syncObject) {
            if (!syncObject.isTaskFinished) {
                throw new IllegalStateException("Listener is still listening new datas");
            }
        }

        return this.isEmulator;
    }

    public BooleanHolder getSyncObject() {
        return syncObject;
    }
}
