/*
 * Copyright (c) 1995 Danny Gasparovski.
 * 
 * Please read the file COPYRIGHT for the 
 * terms and conditions of the copyright.
 */

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#define TOWRITEMAX 512

/*
 * Get the difference in 2 times from updtim()
 * Allow for wraparound times, "just in case"
 * x is the greater of the 2 (current time) and y is
 * what it's being compared against.
 */
#define TIME_DIFF(x,y) (x)-(y) < 0 ? ~0-(y)+(x) : (x)-(y)

