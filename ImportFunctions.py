# Import functions
# @author Strackeror
# @category MH

import time
import json
import ghidra




symbolTable = currentProgram.getSymbolTable()

monitor = ghidra.util.task.TaskMonitor.DUMMY

targetName = str(askFile("Import file", "Choose import file"))
targetFile = open(targetName, 'r')
json_dict = json.load(targetFile)

def maskedSearch(values, mask, addr_set = None):
    search_data =ghidra.app.plugin.core.searchmem.SearchData.createSearchData("search", values, mask)
    search_info = ghidra.util.search.memory.SearchInfo(search_data, 2, True, True, 1, False, None)
    select = ghidra.program.util.ProgramSelection(currentProgram.getMinAddress(), currentProgram.getMaxAddress())
    if addr_set is not None:
        select = ghidra.program.util.ProgramSelection(addr_set)
    alg = search_info.createSearchAlgorithm(currentProgram, currentProgram.getMinAddress(), select)
    acc = ghidra.util.datastruct.ListAccumulator()
    alg.search(acc, monitor)
    return [i.getAddress() for i in acc]

def getNamespace(hierarchy):
    namespace = None
    for name in hierarchy:
        next = symbolTable.getNamespace(name, namespace)
        if next is None:
            next = symbolTable.createNameSpace(namespace, name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
        namespace = next
    return namespace
        


def disassembleFunc(addr):
    print "disassembling",addr
    ghidra.app.cmd.disassemble.DisassembleCommand(addr, None, True).applyTo(currentProgram, monitor)

def getFuncInstructions(function):
    instructions = []
    instruction = getFirstInstruction(function)
    while function.getBody().contains(instruction.address):
        instructions += [instruction]
        instruction = instruction.getNext()
        if instruction is None:
            break
    return instructions

def handleReferences(instructions, ref_dic):
    for refname in ref_dic:
        if refname in functions or refname in symbols:
            continue
        ref = ref_dic[refname]
        print "finding", ref,
        instruction_index = ref["instruction"]
        operand_id = ref["operand"]
        operand_obj_id = ref["operand_object"]
        ref_type = ref["type"]
        try:
            target_obj = instructions[instruction_index].getOpObjects(operand_id)[operand_obj_id]
        except:
            print "ERROR ACCESSING REF at instruction:",instruction_index,operand_id,operand_obj_id,ref_type
            print instructions[instruction_index]
            continue
        print target_obj

        addr = None
        if ref_type == "address":
            addr = target_obj
        elif ref_type == "scalar":
            addr = toAddr(target_obj.getValue())
        elif ref_type == "thunked":
            disassembleFunc(target_obj)
            function = createFunction(target_obj, None)
            addr = function.getThunkedFunction(False).getEntryPoint()

        if addr is None:
            continue

        if refname in json_dict["functions"]:
            handleFunction(addr, refname, True)
        elif refname in json_dict["symbols"]:
            handleSymbol(addr, refname)

dt_parser =  ghidra.util.data.DataTypeParser(
    ghidra.app.plugin.core.analysis.DefaultDataTypeManagerService(), 
    ghidra.util.data.DataTypeParser.AllowedDataTypes.ALL)

def handleParams(function, param_arr):
    if len(param_arr) == 0:
        return
    function.setCustomVariableStorage(True)
    while(function.getParameterCount()):
        function.removeParameter(0)
    
    for param_dic in param_arr:
        data_type = dt_parser.parse(param_dic["type"])
        storage = None
        if param_dic.get("register"):
            storage = ghidra.program.model.listing.VariableStorage( 
                currentProgram, [currentProgram.getRegister(param_dic["register"])])
        elif param_dic.get("stack"):
            storage = ghidra.program.model.listing.VariableStorage(
                currentProgram, param_dic["stack"], data_type.getLength()
            )
            
        param = ghidra.program.model.listing.ParameterImpl(
            param_dic["name"], data_type, storage, currentProgram)
        function.addParameter(param, ghidra.program.model.symbol.SourceType.USER_DEFINED)
        


functions = {}
symbols = {}

def handleSymbol(addr, name):
    if name in symbols:
        return
    print "handling symbol",addr,name
    symbol_dict = json_dict["symbols"][name]
    symbol = createSymbol(addr, symbol_dict["name"], False)
    if symbol is None:
        return
    symbol.setNamespace(getNamespace(symbol_dict["namespace"]))
    symbols[name] = symbol

def handleFunction(addr, name, recheck = False):
    print "handling function",addr,name
    disassembleFunc(addr)
    func_dict = json_dict["functions"][name]
    func = createFunction(addr, func_dict["name"])
    if func is None:
        func = getFunctionAt(addr)
        if func is None:
            return
        func.setName(func_dict["name"], ghidra.program.model.symbol.SourceType.USER_DEFINED)

    functions[name] = func
    func.getSymbol().setNamespace(getNamespace(func_dict["namespace"]))

    if "prototype" in func_dict:
        parser = ghidra.app.util.parser.FunctionSignatureParser(currentProgram.getDataTypeManager(), ghidra.app.plugin.core.analysis.DefaultDataTypeManagerService())
        sig = parser.parse(func.getSignature(), func_dict["prototype"])
        ghidra.app.cmd.function.ApplyFunctionSignatureCmd(func.getEntryPoint(), sig, ghidra.program.model.symbol.SourceType.USER_DEFINED).applyTo(currentProgram, monitor)
        print "setting",(sig.getPrototypeString())
    
    handleParams(func, func_dict["params"])

    tags = func_dict["tags"]
    for tag in tags:
        func.addTag(tag)
    if func_dict.get("comment", None):
        func.setComment(func_dict["comment"])
    if 'OBFUSCATED' in tags:
        print 'Skipping obfuscated function'
        return
    if recheck:
        print "rechecking",
        search = func_dict["search"]
        res = maskedSearch(search["value"], search["mask"], func.getBody())
        if len(res) != 1:
            print "failure"
            return
        print "success"
    instructions = getFuncInstructions(func)
    for flow in func_dict["flow"]:
        instructions[flow["id"]].setFlowOverride(
            ghidra.program.model.listing.FlowOverride.valueOf(flow["flow"]))
    handleReferences(instructions,func_dict["references"])

function_order = json_dict["functions"].items()
function_order.sort(key = lambda (_, fd): fd["refcount"])

for name, func in function_order:
    if name in functions or 'OBFUSCATED' in func["tags"]:
        continue
    print "searching for", name,
    addrs = maskedSearch(func["search"]["value"], func["search"]["mask"])
    if len(addrs) != 1:
        print 'function not found'
        continue
    print 'function found'
    handleFunction(addrs[0], name)
    if (func["refcount"] < 0):
        break


for name in json_dict["functions"]:
    if name not in functions:
        print name, "NOT FOUND"

