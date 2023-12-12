package com.experiments.antianalysisproofsample;

import androidx.appcompat.app.AppCompatActivity;

import android.app.Activity;
import android.content.Context;
import android.graphics.Color;
import android.os.Bundle;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.experiments.antianalysisproofsample.models.EvasiveControls;

public class EvasiveControlsActivity extends AppCompatActivity {
    private static final String TAG = EvasiveControlsActivity.class.getCanonicalName();

    private int getScreenWidth(Context context) {
        DisplayMetrics displayMetrics = new DisplayMetrics();
        ((Activity)context).getWindowManager().getDefaultDisplay().getMetrics(displayMetrics);
        return displayMetrics.widthPixels;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_evasive_controls);

        FrameLayout.LayoutParams layoutParamsBox1 =
                new FrameLayout.LayoutParams(
                        (int)(getScreenWidth(this) * 0.7), ViewGroup.LayoutParams.WRAP_CONTENT);
        layoutParamsBox1.setMargins(10, 4, 5, 4);

        FrameLayout.LayoutParams layoutParamsBox2 =
                new FrameLayout.LayoutParams(
                        (int)(getScreenWidth(this) * 0.3), ViewGroup.LayoutParams.WRAP_CONTENT);
        layoutParamsBox2.setMargins(10, 4, 10, 4);

        LinearLayout linearLayout = (LinearLayout) findViewById(R.id.evasive_controls_list);
        linearLayout.setOrientation(LinearLayout.VERTICAL);

        Bundle bundle = getIntent().getExtras();
        String targetClass = bundle.getString("target");
        EvasiveControls evasiveControls = MainActivity.EVASIVE_CONTROLS.get(targetClass);
        assert evasiveControls != null;

        TextView titleTextView = new TextView(this);
        titleTextView.setText(evasiveControls.getLabel());
        titleTextView.setTextSize(28);
        titleTextView.setTextColor(Color.parseColor("#5858dd"));
        titleTextView.setBackgroundColor(Color.parseColor("#bdbdbd"));
        titleTextView.setGravity(Gravity.CENTER);
        // titleTextView.setLayoutParams(layoutParams);
        linearLayout.addView(titleTextView);

        // Add global key
        LinearLayout entry = new LinearLayout(this);
        entry.setOrientation(LinearLayout.HORIZONTAL);
        // entry.setGravity(Gravity.CENTER);

        TextView t1 = new TextView(this);
        t1.setText(evasiveControls.getGlobalControl().getLabel());
        t1.setTextSize(18);
        t1.setLayoutParams(layoutParamsBox1);
        entry.addView(t1);

        // boolean value = bundle.getBoolean(bundle.getString("global key"));
        TextView globalResultTextView = new TextView(this);
        globalResultTextView.setText("Computing ...");
        globalResultTextView.setTextSize(18);
        globalResultTextView.setLayoutParams(layoutParamsBox2);
        entry.addView(globalResultTextView);
        linearLayout.addView(entry);

        // Add line
        for (int i = 0; i < 2; i ++) {
            View v = new View(this);
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    4
            );
            lp.bottomMargin = 8;
            v.setLayoutParams(lp);
            v.setBackgroundColor(Color.parseColor("#B3B3B3"));
            linearLayout.addView(v);
        }

        TextView textView = new TextView(this);
        textView.setText("Specific controls");
        textView.setTextSize(22);
        textView.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));
        textView.setGravity(Gravity.CENTER);
        linearLayout.addView(textView);

        Context context = this;
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                boolean globalResult = false;

                int i = 0;
                for (EvasiveControls.EvasiveMethod evasiveMethod : evasiveControls.getSpecificControls()) {
                    Log.d(TAG, "Starting method : " + evasiveMethod.getLabel());
                    LinearLayout entry = new LinearLayout(context);
                    entry.setOrientation(LinearLayout.HORIZONTAL);
                    // entry.setGravity(Gravity.CENTER);

                    TextView t1 = new TextView(context);
                    t1.setText(evasiveMethod.getLabel());
                    t1.setTextSize(18);
                    t1.setLayoutParams(layoutParamsBox1);
                    entry.addView(t1);

                    TextView t2 = new TextView(context);
                    t2.setTextSize(18);
                    t2.setLayoutParams(layoutParamsBox2);
                    entry.addView(t2);

                    // new Thread(new EvasiveRunner(t2, evasiveMethod, evasiveControls.getInstance())).start();
                    Log.d(TAG, "Running evasive method : " + evasiveMethod.getLabel());
                    Boolean result = evasiveMethod.run(evasiveControls.getInstance());
                    Log.d(TAG, evasiveMethod.getLabel() + " result : " + result);
                    if (result != null) {
                        globalResult |= result;
                        t2.setText(String.valueOf(result));
                        if (result) {
                            t2.setTextColor(Color.parseColor("#ff1312"));
                        } else {
                            t2.setTextColor(Color.parseColor("#13cc13"));
                        }
                    } else {
                        t2.setText("---");
                    }

                    if ((i++ % 2) == 0) {
                        entry.setBackgroundColor(Color.parseColor("#dfdfdf"));
                    }
                    linearLayout.addView(entry);
                }

                globalResultTextView.setText(String.valueOf(globalResult));
                if (globalResult) {
                    globalResultTextView.setTextColor(Color.parseColor("#ff1312"));
                } else {
                    globalResultTextView.setTextColor(Color.parseColor("#13cc13"));
                }
            }
        });
        Log.d(TAG, "Finish onCreate");
    }
}