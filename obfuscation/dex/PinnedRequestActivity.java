package xyz.jserrats.certpin;

import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import java.io.IOException;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class PinnedRequestActivity extends AppCompatActivity {
    public String hostname = "swapi.dev";
    TextView txtString;
    public String url = "https://swapi.dev/api/people/3/";

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView((int) R.layout.activity_plain_request);
        this.txtString = (TextView) findViewById(R.id.txtString);
        try {
            run();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /* access modifiers changed from: package-private */
    public void run() throws IOException {
        new OkHttpClient.Builder().certificatePinner(new CertificatePinner.Builder().add(this.hostname, "sha256/eSiyNwaNIbIkI94wfLFmhq8/ATxm30i973pMZ669tZo=").build()).build().newCall(new Request.Builder().url(this.url).build()).enqueue(new Callback() {
            public void onFailure(Call call, IOException e) {
                Log.d("DEBUG", "Request Failed");
                call.cancel();
                PinnedRequestActivity.this.runOnUiThread(new Runnable() {
                    public void run() {
                        PinnedRequestActivity.this.txtString.setText("Request failed :(");
                    }
                });
                Log.e("ERROR", e.toString());
            }

            public void onResponse(Call call, Response response) throws IOException {
                final String myResponse = response.body().string();
                Log.d("DEBUG", myResponse);
                PinnedRequestActivity.this.runOnUiThread(new Runnable() {
                    public void run() {
                        PinnedRequestActivity.this.txtString.setText(myResponse);
                    }
                });
            }
        });
    }
}
