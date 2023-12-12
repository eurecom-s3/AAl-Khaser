package com.experiments.antianalysisproofsample.models;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

import com.experiments.antianalysisproofsample.EvasiveControlsActivity;
import com.experiments.antianalysisproofsample.MainActivity;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class EvasiveControls {
    private static final String TAG = EvasiveControls.class.getCanonicalName();

    private final String label;
    private final Object instance;
    private final Class<?> targetClass;
    private final EvasiveMethod globalControl;
    private final List<EvasiveMethod> specificControls;

    public EvasiveControls(String label, Class<?> targetClass, Object instance, EvasiveMethod globalControl, List<EvasiveMethod> specificControls) {
        this.label = label;
        this.instance = instance;
        this.globalControl = globalControl;
        this.targetClass = targetClass;
        this.specificControls = specificControls;
    }

    public String getLabel() {
        return label;
    }

    public Object getInstance() {
        return instance;
    }

    public EvasiveMethod getGlobalControl() {
        return globalControl;
    }

    public List<EvasiveMethod> getSpecificControls() {
        return specificControls;
    }

    public static class EvasiveMethod {
        private final String label;
        private final Method targetMethod;
        private final List<Object> parameters;

        public EvasiveMethod(String label, Method targetMethod) {
            this.label = label;
            this.targetMethod = targetMethod;
            this.parameters = new ArrayList<>();
        }

        public EvasiveMethod(String label, Method targetMethod, List<Object> parameters) {
            this.label = label;
            this.targetMethod = targetMethod;
            this.parameters = parameters;
        }

        public Boolean run(Object instance) {
            Object[] objects = null;
            if (this.parameters.size() > 0) {
                objects = this.parameters.toArray();
            }
            try {
                return (boolean) this.targetMethod.invoke(instance, objects);
            } catch (/*IllegalAccessException | InvocationTargetException*/ Exception e) {
                e.printStackTrace();
            }
            return null;
        }

        public String getLabel() {
            return label;
        }
    }

}
