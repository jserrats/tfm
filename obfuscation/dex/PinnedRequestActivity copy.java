package xyz.jserrats.certpin;

import a.b.a.j;
import android.os.Bundle;
import android.widget.TextView;
import c.a.g;
import c.a.k;
import c.d.b.e;
import d.B;
import d.C;
import d.C0159f;
import d.C0160g;
import d.a.h.c;
import d.z;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet; 
import java.util.Set;

public class PinnedRequestActivity extends j {
    public TextView r;
    public String s = "swapi.dev";
    public String t = "https://swapi.dev/api/people/3/";

    public void n() {
        Set set;
        int i;
        ArrayList arrayList = new ArrayList();
        String str = this.s;
        String[] strArr = {"sha256/eSiyNwaNIbIkI94wfLFmhq8/ATxm30i973pMZ669tZo="};
        if (str != null) {
            for (String a2 : strArr) {
                arrayList.add(C0160g.f2573b.a(str, a2));
            }
            int size = arrayList.size();
            if (size == 0) {
                set = k.f2078a;
            } else if (size != 1) {
                int size2 = arrayList.size();
                if (size2 < 3) {
                    i = size2 + 1;
                } else {
                    i = size2 < 1073741824 ? size2 + (size2 / 3) : Integer.MAX_VALUE;
                }
                set = new LinkedHashSet(i);
                g.a(arrayList, set);
            } else {
                set = Collections.singleton(arrayList.get(0));
                e.a((Object) set, "java.util.Collections.singleton(element)");
            }
            C0160g gVar = new C0160g(set, (c) null);
            z.a aVar = new z.a();
            aVar.u = gVar;
            z zVar = new z(aVar);
            C.a aVar2 = new C.a();
            aVar2.b(this.t);
            B.a(zVar, aVar2.a(), false).a((C0159f) new c(this));
            return;
        }
        e.a("pattern");
        throw null;
    }

    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView((int) R.layout.activity_plain_request);
        this.r = (TextView) findViewById(R.id.txtString);
        try {
            n();
        } catch (IOException e2) {
            e2.printStackTrace();
        }
    }
}
