#!/bin/sh
# Included in generated package preinstall scripts. No state is modified here.
# Explicit same-version replacement: EGUARD_NAC_REINSTALL=1 (or Windows --reinstall).
set -eu
old=unknown
if [ -x "$NAC_INSTALLED_BINARY" ]; then
 old=$("$NAC_INSTALLED_BINARY" version 2>/dev/null) || old=unknown
fi
awk -v old="$old" -v nextversion="$NAC_NEW_VERSION" -v reinstall="${EGUARD_NAC_REINSTALL:-0}" '
function numeric(s) { return s ~ /^[0-9]+$/ }
function valid(v, a, n, i, core, pre) {
 n=split(v,a,"+"); if(n>2 || (n==2 && a[2] !~ /^[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*$/)) return 0
 core=a[1]; pre=core; sub(/^[^-]*-/,"",pre)
 if(index(core,"-")) {
  if(pre !~ /^[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*$/) return 0
  n=split(pre,a,"."); for(i=1;i<=n;i++) if(numeric(a[i]) && a[i] ~ /^0[0-9]/) return 0
 }
 sub(/-.*/,"",core); n=split(core,a,"."); if(n!=3) return 0
 for(i=1;i<=n;i++) if(!numeric(a[i]) || a[i] ~ /^0[0-9]/) return 0
 return 1
}
function numcmp(a,b) { if(length(a)!=length(b)) return length(a)>length(b)?1:-1; return ("x" a)==("x" b)?0:(("x" a)>("x" b)?1:-1) }
function cmp(a,b, ac,bc,ap,bp,aa,bb,n,m,i,c) {
 sub(/\+.*/,"",a);sub(/\+.*/,"",b)
 ac=a;bc=b;sub(/-.*/,"",ac);sub(/-.*/,"",bc)
 split(ac,aa,".");split(bc,bb,".");for(i=1;i<=3;i++){c=numcmp(aa[i],bb[i]);if(c) return c}
 ap=index(a,"-")?substr(a,index(a,"-")+1):"";bp=index(b,"-")?substr(b,index(b,"-")+1):""
 if(ap==bp)return 0;if(ap=="")return 1;if(bp=="")return -1
 n=split(ap,aa,".");m=split(bp,bb,".");for(i=1;i<=n&&i<=m;i++){
  if(numeric(aa[i])&&numeric(bb[i]))c=numcmp(aa[i],bb[i]);else if(numeric(aa[i]))c=-1;else if(numeric(bb[i]))c=1;else c=(aa[i]==bb[i]?0:(aa[i]>bb[i]?1:-1));if(c)return c
 }
 return n==m?0:(n>m?1:-1)
}
BEGIN {
 if(!valid(nextversion)){print "Invalid new semver" > "/dev/stderr";exit 1}
 if(old=="0.0.0-dev" || !valid(old))exit 0
 c=cmp(nextversion,old);if(c>0 || (c==0 && reinstall==1))exit 0
 print "Downgrade/same version refused; same version requires EGUARD_NAC_REINSTALL=1" > "/dev/stderr";exit 1
}'
