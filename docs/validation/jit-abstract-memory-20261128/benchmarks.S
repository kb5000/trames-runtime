.arch armv8.2-a+lse
.text
// abstract-release-acquire
ldar x0,[x1]
add x0,x0,#1
stlr x0,[x1]
subs x2,x2,#1
b.ne #-16
svc #0
// abstract-atomic
ldaddal x4,x0,[x1]
subs x2,x2,#1
b.ne #-8
svc #0
