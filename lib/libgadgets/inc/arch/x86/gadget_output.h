/*
    ROPit - Gadget generator tool
    Copyright (C) 2011  m_101

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _GADGET_OUTPUT_H_
#define _GADGET_OUTPUT_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* colors */
#define COLOR_PURPLE    "\033[95m"
#define COLOR_BLUE      "\033[94m"
#define COLOR_GREEN     "\033[92m"
#define COLOR_YELLOW    "\033[93m"
#define COLOR_RED       "\033[91m"
#define COLOR_WHITE     "\033[0m"

int gadget_output_format_stack (struct gadget_t *gadget, int color);
int gadget_output_format_line (struct gadget_t *gadget, int color);

#endif /* _GADGET_OUTPUT_H_ */
