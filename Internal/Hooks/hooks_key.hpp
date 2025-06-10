/*
hooks_key.hpp
-> Set hooks for registry key functions.
-> By AwesomeMc101/CDH for Tensora Softworks
6/10/25
*/

#include <Windows.h>
#include <string>
#include <ntstatus.h>

BOOL hookZwCreateKey();
BOOL hookZwOpenKey();
BOOL hookZwDeleteKey();
