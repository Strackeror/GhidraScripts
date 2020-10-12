from __future__ import print_function
from ghidra.program.model.address import Address

import platform
import ghidra

if (platform.system() != "Java"):
    from ghidra_builtins import *

monitor = ghidra.util.task.TaskMonitor.DUMMY

def getFuncInstructions(function):
    instructions = []
    instruction = getFirstInstruction(function)
    while function.getBody().contains(instruction.address):
        instructions += [instruction]
        instruction = instruction.getNext()
        if instruction is None:
            break
    return instructions

def getNamespace(hierarchy):
    symbolTable = currentProgram.getSymbolTable()
    namespace = None
    for name in hierarchy:
        next = symbolTable.getNamespace(name, namespace)
        if next is None:
            next = symbolTable.createNameSpace(namespace, name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
        namespace = next
    return namespace

def maskedSearch(values, mask, addr_set = None, max_count = 99):
    # type: (...) -> List[Address]
    search_data = ghidra.app.plugin.core.searchmem.SearchData.createSearchData(
        "search", values, mask)
    search_info = ghidra.util.search.memory.SearchInfo(search_data, max_count, True, True, 1, False, None)
    select = ghidra.program.util.ProgramSelection(currentProgram.getMinAddress(), currentProgram.getMaxAddress())
    if addr_set is not None:
        select = ghidra.program.util.ProgramSelection(addr_set)
    alg = search_info.createSearchAlgorithm(currentProgram, currentProgram.getMinAddress(), select)
    acc = ghidra.util.datastruct.ListAccumulator()
    alg.search(acc, monitor)
    return [i.getAddress() for i in acc]

def findResourcePtr(name, vtableStartOffset):
    namespace = getNamespace(['MH', 'Quest', name])
    search = 'r' + name
    addr = maskedSearch([ord(i) for i in search],
                        [-1 for _ in search], max_count=1)[0]  # type: Address
    data = createData(addr.add(vtableStartOffset), ghidra.program.model.data.PointerDataType())
    createLabel(data.getAddress(), "ResourceVtable", False).setNamespace(namespace)
    print(addr.add(vtableStartOffset))
    addr = toAddr(getLong(addr.add(vtableStartOffset)))
    ghidra.app.cmd.disassemble.DisassembleCommand(addr, None, True).applyTo(currentProgram, monitor)
    func = createFunction(addr, "ResourceFunc")
    instructions = getFuncInstructions(func)
    instruction = instructions[3]
    addr = instruction.getOpObjects(1)[0]
    symbol = createLabel(toAddr(addr.getValue()), "ResourcePtr", False)
    symbol.setNamespace(namespace)
    func.setParentNamespace(namespace)

findResourcePtr('QuestData', -0x58)
findResourcePtr('QuestNoList', -0x18)
