#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise production policy and installer method with boundary fakes; no phone changes."""
from pathlib import Path
import importlib.util
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('privacy_test', Path(__file__).with_name('test_root_visibility.py'))
privacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(privacy)

JAVA_TEST = r'''
package com.android.server.pm;
import android.app.HeckerAppCompatibility;
import android.content.Context;
import android.os.Process;
import android.os.SystemProperties;
import android.provider.Settings;
import android.util.Slog;
import com.android.server.pm.pkg.PackageStateInternal;
import com.android.server.pm.pkg.SharedUserApi;
import java.util.*;
public class AppCompatibilityTest {
    static int assertions;
    record VisiblePkg(String name, int appId) implements PackageStateInternal {
        public String getPackageName(){return name;} public int getAppId(){return appId;}
    }
    static void check(boolean value) { assertions++; if(!value) throw new AssertionError("assertion "+assertions); }
    static class Pair<A,B> { final A first; final B second; Pair(A a,B b){first=a;second=b;} static <A,B> Pair<A,B> create(A a,B b){return new Pair<>(a,b);} }
    static class PackageManager { static final int INSTALL_APEX=2, VERSION_CODE_HIGHEST=-1, INSTALL_SUCCEEDED=1, INSTALL_FAILED_WRONG_INSTALLED_VERSION=-2, INSTALL_FAILED_VERSION_DOWNGRADE=-3; }
    static class Build { static boolean IS_DEBUGGABLE=true; }
    static class AndroidPackage { int version=10; boolean debug, sdk; long getLongVersionCode(){return version;} boolean isDebuggable(){return debug;} boolean isSdkLibrary(){return sdk;} }
    static class PackageInfoLite { String packageName="org.example.app"; int version=5; }
    static class PackageManagerException extends Exception { PackageManagerException(){super("version downgrade");} }
    static class PackageManagerServiceUtils {
        static boolean isDowngradePermitted(int flags,boolean debug){return (flags&1)!=0;}
        static void checkDowngrade(AndroidPackage old,PackageInfoLite next)throws PackageManagerException {if(next.version<old.version)throw new PackageManagerException();}
        static void checkDowngrade(PackageSetting old,PackageInfoLite next)throws PackageManagerException {if(next.version<10)throw new PackageManagerException();}
    }
    static class PackageSetting { AndroidPackage pkg=new AndroidPackage(); boolean system; int[] users={0}; int getAppId(){return 10101;} AndroidPackage getPkg(){return pkg;} boolean isDebuggable(){return false;} boolean isSystem(){return system;} int[] queryInstalledUsers(int[] all,boolean installed){return users;} }
    static class Store { PackageSetting current=new PackageSetting(), factory; PackageSetting getPackageLPr(String n){return n.equals("org.example.app")?current:null;} PackageSetting getDisabledSystemPkgLPr(PackageSetting p){return factory;} }
    static class UserManager { int[] getUserIds(){return new int[]{0,10};} }
    static class PM { final Object mLock=new Object(); Store mSettings=new Store(); UserManager mUserManager=new UserManager(); }
    final PM mPm=new PM(); static final String TAG="test";
    Pair<Integer,String> verifyReplacingVersionCodeForApex(PackageInfoLite p,long v,int f){return Pair.create(-9,"APEX retains its own path");}
    // PRODUCTION_INSTALLER_METHOD
    static void configure(Context context,int user,String key,String value) {
        Settings.Secure.options.computeIfAbsent(key,k->new HashMap<>()).put(user,value);
        context.resolver.observer.onChange(false,null,user);
    }
    public static void main(String[] args) {
        Context context=new Context(); SystemProperties.enabled=true; HeckerRootVisibility.start(context);
        AppCompatibilityTest install=new AppCompatibilityTest(); PackageInfoLite next=new PackageInfoLite();
        check(install.verifyReplacingVersionCode(next,-1,0).first==-3);
        configure(context,0,"hecker_allow_downgrade_apps","org.example.app");
        check(install.verifyReplacingVersionCode(next,-1,0).first==1);
        check(install.verifyReplacingVersionCode(next,99,0).first==-2);
        check(install.verifyReplacingVersionCode(next,-1,2).first==-9);
        install.mPm.mSettings.current.users=new int[]{0,10};
        check(install.verifyReplacingVersionCode(next,-1,0).first==-3);
        configure(context,10,"hecker_allow_downgrade_apps","org.example.app");
        check(install.verifyReplacingVersionCode(next,-1,0).first==1);
        next.packageName="org.example.other";
        check(install.verifyReplacingVersionCode(next,-1,0).first==1); // new installs unchanged
        next.packageName="org.example.app";
        install.mPm.mSettings.current.system=true;
        install.mPm.mSettings.factory=new PackageSetting(); install.mPm.mSettings.factory.pkg.version=6;
        check(install.verifyReplacingVersionCode(next,-1,0).first==-3); // factory floor even userdebug
        next.version=7; check(install.verifyReplacingVersionCode(next,-1,0).first==1);
        install.mPm.mSettings.factory.pkg=null;
        check(install.verifyReplacingVersionCode(next,-1,0).first==-3);
        install.mPm.mSettings.current.system=false; install.mPm.mSettings.current.pkg=null;
        check(install.verifyReplacingVersionCode(next,-1,0).first==1); // retained data, explicit consent
        configure(context,0,"hecker_allow_downgrade_apps","");
        check(install.verifyReplacingVersionCode(next,-1,0).first==-3);
        configure(context,0,"hecker_hide_custom_rom_apps","org.example.app:org.hecker.suite:com.android.systemui");
        check((HeckerRootVisibility.getCompatibilityFlags("org.example.app",0)&16)!=0);
        check((HeckerRootVisibility.getCompatibilityFlags("org.example.app",10)&16)!=0);
        check((HeckerRootVisibility.getCompatibilityFlags("org.hecker.suite",0)&16)==0);
        check((HeckerRootVisibility.getCompatibilityFlags("com.android.systemui",0)&16)==0);
        VisiblePkg caller=new VisiblePkg("org.example.app",10101), suite=new VisiblePkg("org.hecker.suite",10666);
        check(HeckerRootVisibility.shouldHide(10101,caller,suite));
        check(HeckerRootVisibility.shouldHide(1010101,caller,suite));
        check(!HeckerRootVisibility.shouldHide(1000,caller,suite));
        check(!HeckerRootVisibility.shouldHide(10666,caller,suite));
        check(!HeckerRootVisibility.shouldHide(10101,caller,new VisiblePkg("org.example.normal",10555)));
        SharedUserApi shared=()->Set.of(caller,new VisiblePkg("org.example.shared",10101));
        check(HeckerRootVisibility.shouldHide(10101,shared,suite));
        configure(context,0,"hecker_hide_custom_rom_apps","");
        check(HeckerRootVisibility.shouldHide(10101,caller,suite)); // retired setting cannot disable device-wide policy
        check(HeckerAppCompatibility.ALL_FLAGS==31);
        HeckerAppCompatibility.initialize(16,10101);
        check(android.os.Build.TYPE.equals("user") && android.os.Build.TAGS.equals("release-keys"));
        HeckerAppCompatibility.initialize(0,10101);
        check(android.os.Build.TYPE.equals("userdebug") && android.os.Build.TAGS.equals("test-keys"));
        for(int flags=0;flags<32;flags++) for(int user:new int[]{0,10}) {
            HeckerAppCompatibility.initialize(flags,user*100000+10101);
            for(String table:new String[]{"global","secure","system","config"}) {
                for(String key:new String[]{"development_settings_enabled","adb_enabled","adb_wifi_enabled","screen_brightness","hecker_allow_downgrade_apps"}) {
                    boolean hidden=(flags&4)!=0 && (table.equals("global")||table.equals("secure")) && (key.equals("development_settings_enabled")||key.equals("adb_enabled")||key.equals("adb_wifi_enabled"));
                    check(Objects.equals(hidden?"0":null,HeckerAppCompatibility.settingOverride(table,key,user)));
                    check(HeckerAppCompatibility.settingOverride(table,key,user==0?10:0)==null);
                }
            }
        }
        for(int uid:new int[]{0,1000,2000,1001000}) {
            HeckerAppCompatibility.initialize(15,uid);
            check(HeckerAppCompatibility.settingOverride("global","adb_enabled",uid/100000)==null);
        }
        System.out.println("Production installer + settings policy: "+assertions+" assertions PASS");
    }
}
'''

def main():
    installer=(ROOT/'services/core/java/com/android/server/pm/InstallPackageHelper.java').read_text()
    start=installer.index('    Pair<Integer, String> verifyReplacingVersionCode(')
    end=installer.index('    private Pair<Integer, String> verifyReplacingVersionCodeForApex(',start)
    with tempfile.TemporaryDirectory(prefix='hecker-compatibility-') as folder:
        out=Path(folder)
        stubs=dict(privacy.STUBS)
        stubs['android/util/Slog.java']='package android.util; public class Slog {public static int w(String t,String m){return 0;}}'
        stubs['android/util/Log.java']='package android.util; public class Log {public static int w(String t,String m){return 0;} public static int w(String t,String m,Throwable x){return 0;}}'
        stubs['android/os/Build.java']='package android.os; public class Build {public static String TYPE="userdebug", TAGS="test-keys";}'
        for path,content in stubs.items():
            p=out/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(content)
        test=out/'com/android/server/pm/AppCompatibilityTest.java'
        test.write_text(JAVA_TEST.replace('    // PRODUCTION_INSTALLER_METHOD',installer[start:end]))
        subprocess.run(['java','-m','jdk.compiler/com.sun.tools.javac.Main','-d',str(out/'classes'),
            *map(str,out.rglob('*.java')),
            str(ROOT/'services/core/java/com/android/server/pm/HeckerRootVisibility.java'),
            str(ROOT/'core/java/android/app/HeckerAppCompatibility.java')],check=True)
        subprocess.run(['java','-cp',str(out/'classes'),'com.android.server.pm.AppCompatibilityTest'],check=True)
        cpp=(ROOT/'core/jni/android_os_SystemProperties.cpp').read_text()
        a=cpp.index('jboolean HeckerAppCompatibility_nativeApplyBootProperties(')
        b=cpp.index('\n}  // namespace',a)
        native='''#include <map>\n#include <string>\n#include <cassert>\nusing jboolean=bool;struct JNIEnv{};using jclass=void*;constexpr bool JNI_FALSE=false,JNI_TRUE=true;static unsigned testUid;static int applied;static int romCalls;static bool romEnabled;static bool rom_set(bool enabled){romCalls++;romEnabled=enabled;return true;}static bool (*__libc_hecker_set_rom_hide)(bool)=nullptr;\n#define __BIONIC__ 1\n#define getuid() testUid\nnamespace pif_prop_virt {struct State{std::map<std::string,std::string> exactMap;}; bool install(State&s){applied++;assert(s.exactMap.size()==3);assert(s.exactMap.at("ro.boot.flash.locked")=="1");assert(s.exactMap.at("ro.boot.verifiedbootstate")=="green");assert(s.exactMap.at("ro.boot.vbmeta.device_state")=="locked");return true;}}\n'''+cpp[a:b]+'''\nint main(){for(auto uid:{0u,1000u,2000u,1001000u}){testUid=uid;assert(!HeckerAppCompatibility_nativeApplyBootProperties(nullptr,nullptr));}assert(applied==0);for(auto uid:{10101u,90000u,1010101u}){testUid=uid;assert(HeckerAppCompatibility_nativeApplyBootProperties(nullptr,nullptr));}assert(applied==3);__libc_hecker_set_rom_hide=rom_set;testUid=1000;assert(!HeckerAppCompatibility_nativeConfigureRomHide(nullptr,nullptr,true));assert(romCalls==0);testUid=10101;assert(HeckerAppCompatibility_nativeConfigureRomHide(nullptr,nullptr,true));assert(romEnabled);assert(HeckerAppCompatibility_nativeConfigureRomHide(nullptr,nullptr,false));assert(!romEnabled&&romCalls==2);__libc_hecker_set_rom_hide=nullptr;assert(!HeckerAppCompatibility_nativeConfigureRomHide(nullptr,nullptr,true));}\n'''
        (out/'native.cpp').write_text(native)
        subprocess.run(['g++','-std=c++20','-Wall','-Wextra','-Werror',str(out/'native.cpp'),'-o',str(out/'native')],check=True)
        subprocess.run([str(out/'native')],check=True)
    info=(ROOT/'core/java/android/content/pm/ApplicationInfo.java').read_text()
    for code in ['heckerCompatibilityFlags = orig.heckerCompatibilityFlags;',
                 'dest.writeInt(heckerCompatibilityFlags);','heckerCompatibilityFlags = source.readInt();']:
        assert info.count(code)==1
    assert 'HeckerAppCompatibility.initialize(data.appInfo.heckerCompatibilityFlags' in (ROOT/'core/java/android/app/ActivityThread.java').read_text()
    assert 'HeckerAppCompatibility.initialize(appInfo.heckerCompatibilityFlags' in (ROOT/'core/java/com/android/internal/os/AppZygoteInit.java').read_text()
    print('App/zygote transport, factory downgrade floor and bounded native boot rules: PASS')
    print('Whole-platform build, real Binder parcel transport and phone checks remain required.')

if __name__=='__main__':main()
