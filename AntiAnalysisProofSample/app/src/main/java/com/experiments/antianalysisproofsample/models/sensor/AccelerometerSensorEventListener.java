package com.experiments.antianalysisproofsample.models.sensor;

import android.content.Context;
import android.hardware.Sensor;

import com.experiments.antianalysisproofsample.utils.BooleanHolder;

public class AccelerometerSensorEventListener extends BaseSensorListener {

    public AccelerometerSensorEventListener(Context mContext, int steps, BooleanHolder syncObject) {
        super(mContext, Sensor.TYPE_ACCELEROMETER, steps, syncObject);
    }
}
