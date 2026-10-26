/* SPDX-License-Identifier: GPL-3.0-or-later */
#define INFINITY (__builtin_inf())
#define NAN (__builtin_nan(""))
extern double scalbn(double, int);
extern double fmod(double, double);
extern double copysign(double, double);
extern double fabs(double);
