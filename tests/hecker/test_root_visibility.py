#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run production package-privacy policy against host Android boundary fakes."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
STUBS = {
'android/net/Uri.java': 'package android.net; public class Uri {}',
'android/os/Binder.java': 'package android.os; public class Binder { public static long clearCallingIdentity(){return 0;} public static void restoreCallingIdentity(long x){} }',
'android/os/Handler.java': 'package android.os; public class Handler { public void post(Runnable r){r.run();} }',
'android/os/Process.java': 'package android.os; public class Process { public static final int FIRST_APPLICATION_UID=10000; }',
'android/os/SystemProperties.java': 'package android.os; public class SystemProperties { public static boolean enabled; public static boolean getBoolean(String k,boolean d){return enabled;} }',
'android/os/UserHandle.java': 'package android.os; public class UserHandle { public static final int USER_ALL=-1; private int id; public UserHandle(int i){id=i;} public int getIdentifier(){return id;} public static int getAppId(int u){return u%100000;} public static int getUserId(int u){return u/100000;} }',
'android/os/UserManager.java': 'package android.os; public class UserManager { public java.util.List<UserHandle> getUserHandles(boolean x){return java.util.List.of(new UserHandle(0),new UserHandle(10));} }',
'android/database/ContentObserver.java': 'package android.database; public class ContentObserver { public ContentObserver(android.os.Handler h){} public void onChange(boolean b,android.net.Uri u,int i){} }',
'android/content/ContentResolver.java': 'package android.content; public class ContentResolver { public android.database.ContentObserver observer; public void registerContentObserver(android.net.Uri u,boolean b,android.database.ContentObserver o,int i){observer=o;} }',
'android/content/Context.java': 'package android.content; public class Context { public final ContentResolver resolver=new ContentResolver(); public ContentResolver getContentResolver(){return resolver;} public <T>T getSystemService(Class<T> c){return c.cast(new android.os.UserManager());} }',
'android/provider/Settings.java': 'package android.provider; public class Settings { public static class Secure { public static java.util.Map<Integer,String> values=new java.util.HashMap<>(); public static android.net.Uri getUriFor(String k){return new android.net.Uri();} public static String getStringForUser(android.content.ContentResolver c,String k,int u){return values.get(u);} } }',
'android/util/Slog.java': 'package android.util; public class Slog { public static int w(String t,String m){return 0;} }',
'com/android/server/FgThread.java': 'package com.android.server; public class FgThread { public static android.os.Handler getHandler(){return new android.os.Handler();} }',
'com/android/server/pm/pkg/PackageStateInternal.java': 'package com.android.server.pm.pkg; public interface PackageStateInternal { int getAppId(); String getPackageName(); }',
'com/android/server/pm/pkg/SharedUserApi.java': 'package com.android.server.pm.pkg; public interface SharedUserApi { java.util.Set<PackageStateInternal> getPackageStates(); }',
}
TEST = r'''
package com.android.server.pm;
import android.content.Context;
import android.os.SystemProperties;
import android.provider.Settings;
import com.android.server.pm.pkg.PackageStateInternal;
import com.android.server.pm.pkg.SharedUserApi;
public class RootVisibilityTest {
    record P(int id, String name) implements PackageStateInternal {
        public int getAppId(){return id;} public String getPackageName(){return name;}
    }
    static void expect(boolean value) { if(!value) throw new AssertionError(); }
    public static void main(String[] args) {
        Context context=new Context();
        P bank=new P(10101,"org.example.bank"), manager=new P(10200,"com.rifsxd.ksunext");
        Settings.Secure.values.put(0,"org.example.bank:invalid input:org.example.other");
        HeckerRootVisibility.start(context);
        expect(!HeckerRootVisibility.shouldHide(10101,bank,manager)); // disabled build
        SystemProperties.enabled=true;
        HeckerRootVisibility.start(context);
        expect(HeckerRootVisibility.shouldHide(10101,bank,manager));
        expect(!HeckerRootVisibility.shouldHide(1000,bank,manager)); // system management
        expect(!HeckerRootVisibility.shouldHide(10200,manager,manager)); // self
        expect(!HeckerRootVisibility.shouldHide(10101,bank,new P(10101,"org.example.bank")));
        expect(!HeckerRootVisibility.shouldHide(10101,bank,new P(10300,"org.hecker.netlab")));
        expect(!HeckerRootVisibility.shouldHide(10102,new P(10102,"org.example.bank.clone"),manager));
        expect(!HeckerRootVisibility.shouldHide(1010101,bank,manager)); // other Android user
        SharedUserApi shared=()->java.util.Set.of(bank,new P(10101,"org.example.shared"));
        expect(HeckerRootVisibility.shouldHide(10101,shared,manager));
        Settings.Secure.values.put(10,"org.example.bank");
        context.resolver.observer.onChange(false,null,10);
        expect(HeckerRootVisibility.shouldHide(1010101,bank,manager));
        Settings.Secure.values.remove(0);
        context.resolver.observer.onChange(false,null,0);
        expect(!HeckerRootVisibility.shouldHide(10101,bank,manager)); // reversible
        expect(HeckerRootVisibility.shouldHide(1010101,bank,manager));
        System.out.println("Production privacy policy: build gate, target matching, users, shared UID, self/system access and reversal PASS");
    }
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='hecker-root-privacy-') as folder:
        out=Path(folder)
        for name, source in STUBS.items():
            p=out/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(source)
        test=out/'com/android/server/pm/RootVisibilityTest.java';test.write_text(TEST)
        source=ROOT/'services/core/java/com/android/server/pm/HeckerRootVisibility.java'
        subprocess.run(['java','-m','jdk.compiler/com.sun.tools.javac.Main','-d',str(out/'classes'),
                        *map(str,out.rglob('*.java')),str(source)],check=True)
        subprocess.run(['java','-cp',str(out/'classes'),'com.android.server.pm.RootVisibilityTest'],check=True)

if __name__=='__main__':main()
