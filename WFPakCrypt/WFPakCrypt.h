#pragma once

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <string.h>
#include <fstream>
#include <filesystem>
#include <vector>
#include <sstream>


#define LTC_SOURCE
#define LTC_NO_PROTOTYPES
#include <tomcrypt.h>
#undef LTC_SOURCE
#undef LTC_NO_PROTOTYPES


#include "StdLib.h"
#include "Classes.h"
#include "ZipEncrypt.h"
#include "ZipDir.h"