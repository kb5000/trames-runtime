.text
sshll v0.8h, v1.8b, #3
sqxtn v0.8b, v0.8h
saddl v0.8h, v1.8b, v2.8b
sqrshrn2 v0.16b, v1.8h, #4
mla v0.8h, v1.8h, v2.h[7]
mls v0.8h, v1.8h, v2.h[7]
sqdmull v0.4s, v1.4h, v2.h[7]
sqrdmlah v0.8h, v1.8h, v2.h[7]
frecpe v0.4s, v1.4s
frecps v0.4s, v1.4s, v0.4s
frsqrte v0.4s, v1.4s
frsqrts v0.4s, v1.4s, v0.4s
sdot v0.4s, v1.16b, v2.16b
smmla v0.4s, v1.16b, v2.16b
bfdot v0.4s, v1.8h, v2.8h
fmlal v0.4s, v1.4h, v2.4h
fcmla v0.4s, v1.4s, v2.4s, #90
fadd v0.8h, v1.8h, v2.8h
