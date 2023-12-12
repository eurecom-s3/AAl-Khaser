package com.experiments.antianalysisproofsample.models.sensor;

import android.content.Context;
import android.hardware.Sensor;

import com.experiments.antianalysisproofsample.utils.BooleanHolder;

public class GyroscopeSensorEventListener extends BaseSensorListener {

    public GyroscopeSensorEventListener(Context mContext, int steps, BooleanHolder syncObject) {
        super(mContext, Sensor.TYPE_GYROSCOPE, steps, syncObject);
    }
}
