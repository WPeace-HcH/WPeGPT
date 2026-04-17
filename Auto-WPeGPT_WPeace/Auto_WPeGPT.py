import os
import idc
import idaapi
import idautils
import re
import ida_name
from collections import defaultdict
from anytree import Node, RenderTree
import sys
sys.setrecursionlimit(500)


def makeDir():
    cwd = os.getcwd()
    idb_path = idc.get_idb_path()
    idb_name = os.path.basename(idb_path)
    idb_name = 'WPe_' + idb_name
    folder_path = os.path.join(cwd, idb_name) + '\\'
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
        print("Auto-WPeGPT have created the dir:", '"' + folder_path + '"', ":)@WPeace")
    else:
        print("Auto-WPeGPT have found the dir:", '"' + folder_path + '"', ":)@WPeace")
    return folder_path

def getEffectiveStrings(fileDir):
    startAddr = idc.get_name_ea_simple("_start")
    if startAddr == 0xffffffff or startAddr == 0xffffffffffffffff:
        startAddr = idc.get_name_ea_simple("__start")
        if startAddr == 0xffffffff or startAddr == 0xffffffffffffffff:
            startAddr = idc.get_name_ea_simple("start")
    if startAddr == 0xffffffff or startAddr == 0xffffffffffffffff:
        startAddr = idc.get_segm_by_sel(idc.selector_by_name(".text"))
    if startAddr == 0xffffffff or startAddr == 0xffffffffffffffff:
        print("Get startAddress failed. @WPeace")
        return 0
    textStartAddr = idc.get_segm_start(startAddr)
    textEndAddr = idc.get_segm_end(startAddr)
    strList = []
    for s in idautils.Strings():
        if str(s) in strList:
            continue
        sysFlag = 0
        xrefCount = len(list(idautils.XrefsTo(s.ea)))
        if xrefCount != 0:
            for xref in idautils.XrefsTo(s.ea):
                strUseAddr = xref.frm
                funcName = idc.get_func_name(strUseAddr)
                funcAddr = idc.get_name_ea_simple(funcName)
                if textStartAddr < funcAddr < textEndAddr:
                    sysFlag = 0
                    break
                elif len(re.findall("^_.*", funcName)) != 0:
                    sysFlag = 1
                else:
                    func_ea = idc.get_name_ea_simple(funcName)
                    for xcaller in idautils.XrefsTo(func_ea):
                        callerFuncName = idc.get_func_name(xcaller.frm)
                        callerFuncAddr = idc.get_name_ea_simple(callerFuncName)
                        if textStartAddr < callerFuncAddr < textEndAddr:
                            sysFlag = 0
                            break
                        elif len(re.findall("^_.*", callerFuncName)) != 0:
                            sysFlag = 1
                        else:
                            sysFlag = 1
            if sysFlag == 0:
                string = str(s).replace('\n', '').replace('\r', '').replace('\a', '').replace('\t', '').replace(' ', '')
                if 0 < len(string) < 50:
                    strList.append(string)
    filename = fileDir + "effectiveStrings.txt"
    with open(filename, 'w', encoding='utf-8') as fp:
        for line in strList:
            print(line, file=fp)
    print("EffectiveStrings results are output to the file...")

def printTargetNode(node, name, filename, indent=0, level_printed=None):
    if level_printed is None:
        level_printed = {0: set()}
    if node.name == name and node.name not in level_printed[indent]:
        with open(filename, 'a') as fp:
            print(' ' * indent + node.name, file=fp)
        level_printed[indent].add(node.name)
        if indent + 4 not in level_printed:
            level_printed[indent + 4] = set()
        for child in node.children:
            printTargetNode(child, child.name, filename, indent + 4, level_printed)
    else:
        for child in node.children:
            printTargetNode(child, name, filename, indent, level_printed)

class MyNode:
    def __init__(self, name):
        self.name = name
        self.parents = []
        self.children = []

# 通过递归获取调用树，结果全面但是只适用于函数较少时。
def createRecursionTree(data, fileDir):
    try:
        root = MyNode('WPeace-HcH')
        nodes = {}
        for key in data.keys():
            if key not in nodes:
                nodes[key] = MyNode(key)
                nodes[key].parents.append(root)
                root.children.append(nodes[key])
            for value in data[key]:
                if value not in nodes:
                    nodes[value] = MyNode(value)
                if value not in [child.name for child in nodes[key].children]:
                    nodes[value].parents.append(nodes[key])
                    nodes[key].children.append(nodes[value])
                    if nodes[value] in root.children:
                        root.children.remove(nodes[value])
        funcTree_filename = fileDir + "funcTree.txt"
        with open(funcTree_filename, 'w', encoding='utf-8') as fp:
            for pre, fill, node in RenderTree(root):
                print("%s%s" % (pre, node.name), file=fp)
        mainFuncTree_filename = fileDir + "mainFuncTree.txt"
        with open(mainFuncTree_filename, 'w', encoding='utf-8') as fp:
            pass
        # 尝试遍历找寻main函数或WinMain
        mainFuncName = "main"   #默认main函数为主函数
        for segea in idautils.Segments():
            for function_ea in idautils.Functions(segea, idc.get_segm_end(segea)):
                funcName = idc.get_func_name(function_ea)
                if "winmain" in funcName.lower():
                    mainFuncName = funcName
        printTargetNode(root, mainFuncName, mainFuncTree_filename)
        return 1
    except:
        return -1

# 通过Anytree Node获取调用树，适用范围广，在函数数量高时使用。
def createAnyTree(data, fileDir):
    root = Node('WPeace-HcH')
    nodes = {}
    for key in data.keys():
        if key in nodes:
            parent_node = nodes[key]
        else:
            parent_node = Node(key, parent=root)
            nodes[key] = parent_node
        for value in data[key]:
            if value in nodes and nodes[value].parent is None:
                child_node = nodes[value]
                child_node.parent = parent_node
            else:
                child_node = Node(value, parent=parent_node)
                nodes[value] = child_node
    funcTree_filename = fileDir + "funcTree.txt"
    with open(funcTree_filename, 'w', encoding='utf-8') as fp:
        for pre, fill, node in RenderTree(root):
            print("%s%s" % (pre, node.name), file=fp)
    mainFuncTree_filename = fileDir + "mainFuncTree.txt"
    with open(mainFuncTree_filename, 'w', encoding='utf-8') as fp:
        pass
    # 尝试遍历找寻main函数或WinMain
    mainFuncName = "main"   #默认main函数为主函数
    for segea in idautils.Segments():
        for function_ea in idautils.Functions(segea, idc.get_segm_end(segea)):
            funcName = idc.get_func_name(function_ea)
            if "winmain" in funcName.lower():
                mainFuncName = funcName
    printTargetNode(root, mainFuncName, mainFuncTree_filename)

def getCallRelation(outputFileDir):
    # 获取代码段相关函数
    startAddr = idc.get_name_ea_simple("_start")
    if startAddr == 0xffffffff or startAddr == 0xffffffffffffffff:
        startAddr = idc.get_name_ea_simple("__start")
        if startAddr == 0xffffffff or startAddr == 0xffffffffffffffff:
            startAddr = idc.get_name_ea_simple("start")
    if startAddr == 0xffffffff or startAddr == 0xffffffffffffffff:
        startAddr = idc.get_segm_by_sel(idc.selector_by_name(".text"))
    if startAddr == 0xffffffff or startAddr == 0xffffffffffffffff:
        print("Get startAddress failed. @WPeace")
        return 0
    # 列表funcDict存放重要函数
    funcDict = defaultdict(list)
    for function_ea in idautils.Functions(idc.get_segm_start(startAddr), idc.get_segm_end(startAddr)):
        funcName = idc.get_func_name(function_ea)
        if len(re.findall("^__.*", funcName)) != 0 or funcName == "syscall" or funcName == "start" or '@' in funcName or '?' in funcName:
            if "WinMain" not in funcName:
                continue
        for ref_ea in idautils.CodeRefsTo(function_ea, 0):
            callerFunc = idc.get_func_name(ref_ea)
            if (len(re.findall("^__.*", callerFunc)) == 0 and callerFunc != "" and '@' not in callerFunc and '?' not in callerFunc) or "WinMain" in callerFunc:
                funcDict[callerFunc].append(funcName)
    for callerFunc in funcDict:
        funcDict[callerFunc] = list(set(funcDict[callerFunc]))
    # 尝试利用idata段获取相关导入函数
    idataStartAddr = idc.get_segm_by_sel(idc.selector_by_name(".idata"))
    idataEndAddr = idc.get_segm_end(idataStartAddr)
    for api_ea in idautils.Heads(idataStartAddr, idataEndAddr):
        funcName = ida_name.get_name(api_ea)
        for api_ref_ea in idautils.CodeRefsTo(api_ea, 0):
            callerFunc = idc.get_func_name(api_ref_ea)
            if len(re.findall("^__.*", callerFunc)) == 0 and callerFunc != "" and '@' not in callerFunc and '?' not in callerFunc:
                if len(re.findall("^__.*", funcName)) == 0:
                    funcDict[callerFunc].append(funcName)
    # 尝试利用不同方式创建树结构
    recursion_result = createRecursionTree(funcDict, outputFileDir)
    if recursion_result == 1:
        print("FuncTree results by recursion are output to the file...")
    else:
        createAnyTree(funcDict, outputFileDir)
        print("FuncTree results by anytree are output to the file...")

def main():
    outputFileDir = makeDir()
    getCallRelation(outputFileDir)
    getEffectiveStrings(outputFileDir)


if __name__ == "__main__":
    main()
