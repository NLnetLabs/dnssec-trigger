#if !defined(AFX_STDAFX_H__780690DC_E128_403D_BC07_780D1B2CC101__INCLUDED_)
#define AFX_STDAFX_H__780690DC_E128_403D_BC07_780D1B2CC101__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
#define NOGDI

#include <windows.h>

#include <string.h> // String management...
#include <stdio.h>
#include <stdbool.h>

#ifdef BORLANDC
  #include <string.h>
  #include <ctype.h>
#endif

//To make it a NSIS Plug-In
#include "exdll.h"

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_STDAFX_H__780690DC_E128_403D_BC07_780D1B2CC101__INCLUDED_)
