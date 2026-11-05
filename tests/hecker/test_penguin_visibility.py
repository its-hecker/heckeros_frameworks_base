#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute the imported visibility decisions with system/shared-user/Home boundaries."""
from pathlib import Path
import importlib.util
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('privacy', Path(__file__).with_name('test_root_visibility.py'))
privacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(privacy)


def main():
    source = (ROOT/'services/core/java/com/android/server/pm/AppsFilterBase.java').read_text()
    a = source.index('    private static final String PACKAGE_SYSTEMUI')
    b = source.index('    /**\n     * See\n', a)
    methods = source[a:b]
    assert 'import android.util.Pair;' in source
    assert source.index('if (shouldHideFromUid(') < source.index('// use cache')
    engine = (ROOT/'services/core/java/com/android/server/pm/ComputerEngine.java').read_text()
    assert engine.count('AppsFilterBase.shouldHideFromUid(') == 3
    assert 'public final String getDefaultHome(@UserIdInt int userId)' in engine
    stubs = dict(privacy.STUBS)
    stubs['android/annotation/NonNull.java'] = 'package android.annotation; public @interface NonNull {}'
    stubs['android/annotation/Nullable.java'] = 'package android.annotation; public @interface Nullable {}'
    stubs['android/util/Pair.java'] = '''package android.util;
public class Pair<A,B>{public final A first;public final B second;public Pair(A a,B b){first=a;second=b;}}'''
    stubs['com/android/server/pm/pkg/PackageStateInternal.java'] = '''package com.android.server.pm.pkg;
public interface PackageStateInternal {int getAppId();String getPackageName();
 default boolean isSystem(){return false;}default boolean isPrivileged(){return false;}
 default boolean hasSharedUser(){return false;}default int getSharedUserAppId(){return 0;}}'''
    stubs['com/android/server/pm/pkg/SharedUserApi.java'] = '''package com.android.server.pm.pkg;
public interface SharedUserApi {java.util.Set<PackageStateInternal> getPackageStates();
 default boolean isPrivileged(){return false;}}'''
    stubs['com/android/server/pm/Computer.java'] = '''package com.android.server.pm;
import com.android.server.pm.pkg.*;import android.util.Pair;
interface Computer {PackageStateInternal getPackageStateInternal(String name);
 Pair<PackageStateInternal,SharedUserApi> getPackageOrSharedUser(int id);SharedUserApi getSharedUser(int id);}'''
    stubs['com/android/server/pm/ComputerEngine.java'] = '''package com.android.server.pm;
import com.android.server.pm.pkg.*;import android.util.Pair;import java.util.*;
class ComputerEngine implements Computer {
 final Map<String,PackageStateInternal> packages=new HashMap<>();
 final Map<Integer,SharedUserApi> shared=new HashMap<>();final Map<Integer,String> homes=new HashMap<>();
 public PackageStateInternal getPackageStateInternal(String name){return packages.get(name);}
 public Pair<PackageStateInternal,SharedUserApi> getPackageOrSharedUser(int id){
  for(var p:packages.values())if(p.getAppId()==id)return new Pair<>(p,null);
  return shared.containsKey(id)?new Pair<>(null,shared.get(id)):null;}
 public SharedUserApi getSharedUser(int id){return shared.get(id);}
 public String getDefaultHome(int user){return homes.get(user);}}'''
    stubs['com/android/server/pm/AppsFilterBase.java'] = '''package com.android.server.pm;
import android.annotation.*;import android.os.UserHandle;import android.os.Process;import android.util.Pair;import com.android.server.pm.pkg.*;
public class AppsFilterBase {'''+methods+'\n}'
    stubs['com/android/server/pm/PenguinVisibilityTest.java'] = r'''
package com.android.server.pm;
import android.content.Context;import android.os.SystemProperties;import android.provider.Settings;
import com.android.server.pm.pkg.*;import java.util.*;
public class PenguinVisibilityTest {
 record P(int id,String name,boolean system,boolean privileged,int shared) implements PackageStateInternal {
  public int getAppId(){return id;}public String getPackageName(){return name;}
  public boolean isSystem(){return system;}public boolean isPrivileged(){return privileged;}
  public boolean hasSharedUser(){return shared!=0;}public int getSharedUserAppId(){return shared;}}
 static int checks;static void check(boolean value){checks++;if(!value)throw new AssertionError("visibility check "+checks);}
 public static void main(String[] args){
  Context context=new Context();SystemProperties.enabled=true;HeckerRootVisibility.start(context);
  ComputerEngine snapshot=new ComputerEngine();
  for(P pkg:List.of(new P(10101,"app.bank",false,false,0),new P(10102,"app.home",false,false,0),
      new P(10103,"app.system",true,false,0),new P(10104,"app.priv",false,true,0),
      new P(10105,"app.shared",false,false,20000),new P(10666,"org.hecker.suite",true,true,0),
      new P(10667,"com.rifsxd.ksunext",false,false,0),new P(10668,"com.crdroid.settings",true,true,0),
      new P(10669,"app.normal",false,false,0),new P(10670,"lineageos.platform",true,true,0)))
   snapshot.packages.put(pkg.name(),pkg);
  for(String target:List.of("org.hecker.suite","com.crdroid.settings","lineageos.platform")){
   check(AppsFilterBase.shouldHideFromUid(snapshot,10101,target));
   check(AppsFilterBase.shouldHideFromUid(snapshot,1010101,target));
   check(!AppsFilterBase.shouldHideFromUid(snapshot,1000,target));
   check(!AppsFilterBase.shouldHideFromUid(snapshot,10103,target));
   check(!AppsFilterBase.shouldHideFromUid(snapshot,10104,target));
  }
  check(!AppsFilterBase.shouldHideFromUid(snapshot,10666,"org.hecker.suite"));
  check(!AppsFilterBase.shouldHideFromUid(snapshot,10101,"app.normal"));
  check(!AppsFilterBase.shouldHideFromUid(snapshot,10101,null));
  check(!AppsFilterBase.shouldHideFromUid(snapshot,10101,"com.rifsxd.ksunext"));
  Settings.Secure.values.put(0,"app.bank");context.resolver.observer.onChange(false,null,0);
  check(AppsFilterBase.shouldHideFromUid(snapshot,10101,"com.rifsxd.ksunext"));
  check(!AppsFilterBase.shouldHideFromUid(snapshot,1010101,"com.rifsxd.ksunext"));
  snapshot.homes.put(0,"app.home");
  check(!AppsFilterBase.shouldHideFromUid(snapshot,10102,"org.hecker.suite"));
  check(AppsFilterBase.shouldHideFromUid(snapshot,1010102,"org.hecker.suite"));
  snapshot.homes.put(10,"app.home");
  check(!AppsFilterBase.shouldHideFromUid(snapshot,1010102,"org.hecker.suite"));
  snapshot.shared.put(20000,()->Set.of(snapshot.packages.get("app.shared"),snapshot.packages.get("app.system")));
  check(!AppsFilterBase.shouldHideFromUid(snapshot,10105,"org.hecker.suite"));
  snapshot.shared.put(20000,()->Set.of(snapshot.packages.get("app.shared")));
  check(AppsFilterBase.shouldHideFromUid(snapshot,10105,"org.hecker.suite"));
  check(HeckerRootVisibility.isRomPackage("org.lineageos.settings"));
  check(!HeckerRootVisibility.isRomPackage("org.lineageosfake.settings"));
  System.out.println(checks+" Penguin visibility checks: ROM catalog, root selection, users, trusted/shared callers, Home and self PASS");
 }
}'''
    with tempfile.TemporaryDirectory(prefix='hecker-penguin-visibility-') as directory:
        out = Path(directory)
        for path, text in stubs.items():
            target=out/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)
        subprocess.run(['java','-m','jdk.compiler/com.sun.tools.javac.Main','-d',str(out/'classes'),
            *map(str,out.rglob('*.java')),
            str(ROOT/'services/core/java/com/android/server/pm/HeckerRootVisibility.java')],check=True)
        subprocess.run(['java','-cp',str(out/'classes'),'com.android.server.pm.PenguinVisibilityTest'],check=True)


if __name__ == '__main__': main()
