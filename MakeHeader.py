from __future__ import print_function

basename = "MH"
symbolTable = currentProgram.getSymbolTable()
functionManager = currentProgram.getFunctionManager()
main_namespace = symbolTable.getNamespace(basename, None)
indent = ""

#targetName = str(askFile("Export file", "Choose export file"))
targetName = r"D:\Dev\GhidraScripts\ghidra_export.h"

targetFile = open(targetName, 'w')

def escapeName(str):
    return str.replace(':', "_").replace('?', '_').replace(' ', '_')

def handleSymbol(symbol):
    print(indent, "static void *{0} = (void*)0x{1};".format( escapeName(symbol.getName()), symbol.getAddress()), file=targetFile, sep='')

def handleFunction(function):
    params = "" 
    #for param in function.getParameters():
    #    params += "," + param.getDataType().toString()
    for i in range(function.getParameterCount()):
        params += "," + function.getParameter(i).getDataType().toString()
    params = params[1:]
    returnType = function.getReturnType().toString()
    if returnType == "undefined":
        returnType = "undefined8"

    print (indent, "static {0}(*{1})({2}) = ({0}(*)({2}))0x{3};".format(
        returnType,
        escapeName(function.getName()),
        params,
        function.getEntryPoint().toString()
    ), file=targetFile, sep='')


def handleNamespace(namespace):
    global indent
    print (indent, "namespace {0} {{".format(namespace.getName()), file=targetFile, sep='')
    indent = indent + "  "
    for symbol in symbolTable.getSymbols(namespace):
        if functionManager.getFunctionAt(symbol.address) is not None:
            handleFunction(functionManager.getFunctionAt(symbol.address))
        elif symbolTable.getNamespace(symbol.getName(), namespace) is not None:
            handleNamespace(symbolTable.getNamespace(symbol.getName(), namespace))
        else:
            handleSymbol(symbol)
    indent = indent[:-2]
    print (indent, "}", file=targetFile, sep='')

print ("""
#pragma once
typedef unsigned char undefined; 
typedef unsigned char undefined1; 
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long long undefined8;
typedef unsigned char byte; 
typedef unsigned long long ulonglong;
typedef long long longlong;
typedef unsigned int uint;
typedef unsigned short ushort;
""", file=targetFile)
handleNamespace(main_namespace)
