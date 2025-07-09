import functools
import idaapi
import ida_hexrays
import ida_kernwin
import idc
import openai
import re
import threading
import json
import httpx
import sys, os
from google import genai

# Windows
path = os.path.dirname(os.path.abspath(__file__)) + "\\Auto-WPeGPT_WPeace\\"
# MacOS
#path = os.path.dirname(os.path.abspath(__file__)) + "/Auto-WPeGPT_WPeace/"
sys.path.append(path)
import Auto_WPeGPT
# Whether to use Chinese explanation code.
ZH_CN = True

# Use ChatGPT
PLUGIN_NAME = 'WPeChat-GPT'
# Use DeepSeek
#PLUGIN_NAME = 'WPeChat-DeepSeek'
# Use gemini
# PLUGIN_NAME = 'WPeChat-Gemini'

# Set your API key here, or put in in the model_api_key environment variable.
model_api_key = "ENTER_API_KEY_HERE"

# Set your forward-proxy if necessary. (e.g. Clash = http://127.0.0.1:7890)
proxy = ""
# Set reverse-proxy-URL or custom-api-URL if you need. (e.g. Azure OpenAI)
proxy_address = ""


# Plugin information, you can change the model here.
if PLUGIN_NAME == "WPeChat-GPT":
    PROD_NAME = 'ChatGPT'
    MODEL = 'gpt-4'
    print("WPeChatGPT is using ChatGPT.")
elif PLUGIN_NAME == "WPeChat-DeepSeek":
    PROD_NAME = 'DeepSeek'
    MODEL = 'deepseek-chat'
    print("WPeChatGPT is using DeepSeek.")
elif PLUGIN_NAME == "WPeChat-Gemini":
    PROD_NAME = 'Gemini'
    # MODEL = 'gemini-2.5-pro'
    MODEL = 'gemini-2.5-flash'
    print("WPeChatGPT is using Gemini.")
# Create openai client (python openai package version > 1.2)
if PROD_NAME == "DeepSeek":
    client = openai.OpenAI(base_url="https://api.deepseek.com", api_key=model_api_key)
elif PROD_NAME == "Gemini":
    client = genai.Client(api_key=model_api_key)
elif proxy:
    client = openai.OpenAI(http_client=httpx.Client(proxies=proxy, transport=httpx.HTTPTransport(local_address="0.0.0.0")), api_key=model_api_key)
    print("WPeChatGPT has appointed the forward-proxy.")
elif proxy_address:
    client = openai.OpenAI(base_url=proxy_address, api_key=model_api_key)
    print("WPeChatGPT has appointed the reverse-proxy.")
else:
    client = openai.OpenAI(api_key=model_api_key)


# WPeChatGPT 分析解释函数
class ExplainHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        funcComment = getFuncComment(idaapi.get_screen_ea())
        if "---WPeChat_START---" in funcComment:
            if ZH_CN:
                print("当前函数已经完成过 %s:Explain 分析，请查看注释或删除注释重新分析。@WPeace"%(PLUGIN_NAME))
            else:
                print("The current function has been analyzed by %s:Explain, please check the comment or delete the comment to re-analyze. @WPeace"%(PLUGIN_NAME))
            return 0
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        # 中文
        if ZH_CN:
            query_model_async("下面是一个C语言伪代码函数，分别分析该函数的预期目的、参数的作用、详细功能，最后取一个新的函数名字。（用简体中文回答我，并且回答开始前加上'---WPeChat_START---'字符串结束后加上'---WPeChat_END---'字符串）\n"
                + str(decompiler_output),
                functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v, cmtFlag=0, printFlag=0),
                0)
        # English
        else:
            query_model_async("Analyze the following C language pseudo-code function, respectively speculate on the use environment, expected purpose, and detailed function of the function, and finally choose a new name for this function. (add '---WPeChat_START---' string before the beginning of the answer and add '---WPeChat_END---' string after the end)\n" + str(decompiler_output), functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v, cmtFlag=0, printFlag=0), 0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# WPeChatGPT 重命名变量函数
class RenameHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_model_async("Analyze the following C function:\n" + str(decompiler_output) +
                            "\nSuggest better variable names, reply with a JSON array where keys are the original names"
                            "and values are the proposed names. Do not explain anything, only print the JSON "
                            "dictionary.",
                          functools.partial(rename_callback, address=idaapi.get_screen_ea(), view=v),
                          0)
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# WPeChatGPT 使用python3对函数进行还原
class PythonHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        # lastAddr 为函数的最后一行汇编代码地址
        lastAddr = idc.prev_head(idc.get_func_attr(idaapi.get_screen_ea(), idc.FUNCATTR_END))
        # 获取对应注释
        addrComment = getAddrComment(lastAddr)
        if "---WPeChat_Python_START---" in str(addrComment):
            if ZH_CN:
                print("当前函数已经完成过 %s:Python 分析，请查看注释或删除注释重新分析。@WPeace"%(PLUGIN_NAME))
            else:
                print("The current function has been analyzed by %s:Python, please check the comment or delete the comment to re-analyze. @WPeace"%(PLUGIN_NAME))
            return 0
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        # 中文
        if ZH_CN:
            query_model_async("分析下面的C语言伪代码并用python3代码进行还原。（回答开始前加上'---WPeChat_Python_START---'字符串结束后加上'---WPeChat_Python_END---'字符串）\n"
                + str(decompiler_output),
                functools.partial(comment_callback, address=lastAddr, view=v, cmtFlag=1, printFlag=1),
                0)
        # English
        else:
            query_model_async("Analyze the following C language pseudocode and restore it with python3 code. (Add '---WPeChat_Python_START---' string before the beginning of the answer and add '---WPeChat_Python_END---' string after the end)\n"
                              + str(decompiler_output),
                              functools.partial(comment_callback, address=lastAddr, view=v, cmtFlag=1, printFlag=1),
                              0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# WPeChatGPT 尝试寻找函数漏洞
class FindVulnHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        funcComment = getFuncComment(idaapi.get_screen_ea())
        if "---WPeChat_VulnFinder_START---" in funcComment:
            if ZH_CN:
                print("当前函数已经完成过 %s:VulnFinder 分析，请查看注释或删除注释重新分析。@WPeace"%(PLUGIN_NAME))
            else:
                print("The current function has been analyzed by %s:VulnFinder, please check the comment or delete the comment to re-analyze. @WPeace"%(PLUGIN_NAME))
            return 0
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        # 中文
        if ZH_CN:
            query_model_async("查找下面这个C语言伪代码函数的漏洞并提出可能的利用方法。（用简体中文回答我，并且回答开始前加上'---WPeChat_VulnFinder_START---'字符串结束后加上'---WPeChat_VulnFinder_END---'字符串）\n"
                + str(decompiler_output),
                functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v, cmtFlag=0, printFlag=2),
                0)
        # English
        else:
            query_model_async("Find the following C function vulnerabilty and suggest a possible way to exploit it.(Use English to answer me, and answer before plus '---WPeChat_VulnFinder_START---' the end of the string plus '---WPeChat_VulnFinder_END---' string)\n"
                              + str(decompiler_output),
                              functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v, cmtFlag=0, printFlag=2),
                              0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# WPeChatGPT 尝试对漏洞函数生成EXP
class expCreateHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        funcComment = getFuncComment(idaapi.get_screen_ea())
        if "---WPeChat_VulnPython_START---" in funcComment:
            if ZH_CN:
                print("当前函数已经完成过 %s:ExpCreater 分析，请查看注释或删除注释重新分析。@WPeace"%(PLUGIN_NAME))
            else:
                print("The current function has been analyzed by %s:ExpCreater, please check the comment or delete the comment to re-analyze. @WPeace"%(PLUGIN_NAME))
            return 0
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        # 中文
        if ZH_CN:
            query_model_async("使用Python构造代码来利用下面函数中的漏洞。（用简体中文回答我，并且回答开始前加上'---WPeChat_VulnPython_START---'字符串结束后加上'---WPeChat_VulnPython_END---'字符串）\n"
                + str(decompiler_output),
                functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v, cmtFlag=0, printFlag=3),
                0)
        # English
        else:
            query_model_async("Use Python to construct code to exploit the vulnerabilities in the following functions.(Answer before plus '---WPeChat_VulnPython_START---' the end of the string plus '---WPeChat_VulnPython_END---' string)\n"
                              + str(decompiler_output),
                              functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v, cmtFlag=0, printFlag=3),
                              0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


def autoChatFunc(funcTree:str, strings:str, callback):
    messages = []
    input_funcTree = funcTree
    messages.append({"role": "user", "content": input_funcTree})
    input_strings = strings
    messages.append({"role": "user", "content": input_strings})
    if ZH_CN:
        messages.append({"role": "user", "content": "结合该程序的函数调用结构及其所包含的字符串，猜测其运行目的及功能。"})
        messages.append({"role": "user", "content": "请再仔细分析后告诉我该程序的运行目的及大概功能。"})
    else:
        messages.append({"role": "user", "content": "Combining the function call structure of the program and the strings it contains, guess its purpose and function."})
        messages.append({"role": "user", "content": "Please tell me the purpose and general function of the program after careful analysis."})
    t = threading.Thread(target=chat_api_worker, args=(messages, MODEL, callback))
    t.start()


def chat_api_worker(messages, model, callback):
    try:
        response = client.chat.completions.create(messages=messages, model=model)
    except Exception as e:
        if "maximum context length" in str(e):
            print("此二进制文件的分析数据超过了 GPT-3.5-API 的最大长度！请期待后续版本 :)@WPeace")
            return 0
        elif "Cannot connect to proxy" in str(e):
            print("代理出现问题，请稍后重试或检查代理。@WPeace")
            return 0
        else:
            print(f"General exception encountered while running the query: {str(e)}")
            return 0
    callback(response)


def handle_response(autoGptfolder, response):
    message = response.choices[0].message
    if ZH_CN:
        print("GPT 分析完毕，已将结果输出到文件夹：" + autoGptfolder + " 当中！")
    else:
        print("The GPT analysis is complete and the result has been output to the folder: " + autoGptfolder)
    fp = open(autoGptfolder + "GPT-Result.txt", "w")
    fp.write(message.content)
    fp.close()
    print("Auto-WPeGPT finished! :)@WPeace\n")


# Auto-WPeGPT 自动化分析
class autoHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        Auto_WPeGPT.main()
        idb_path = idc.get_idb_path()
        idb_name = 'WPe_' + os.path.basename(idb_path)
        autoGptfolder = os.path.join(os.getcwd(), idb_name) + '\\'
        functreeFilepath = autoGptfolder + "funcTree.txt"
        mainFunctreeFilepath = autoGptfolder + "mainFuncTree.txt"
        stringsFilepath = autoGptfolder + "effectiveStrings.txt"
        file = open(functreeFilepath, "r")
        functreeData = file.read()
        file.close()
        file = open(mainFunctreeFilepath, "r")
        mainFunctreeData = file.read()
        file.close()
        file = open(stringsFilepath, "r")
        stringsData = file.read()
        file.close()
        funcNumber = idaapi.get_func_qty()
        print("There are %d functions in total in this binary file." %funcNumber)
        if funcNumber < 150:
            callback_autogpt = functools.partial(handle_response, autoGptfolder)
            autoChatFunc(functreeData, stringsData, callback_autogpt)
        else:
            callback_autogpt = functools.partial(handle_response, autoGptfolder)
            autoChatFunc(mainFunctreeData, stringsData, callback_autogpt)
        print("Auto-WPeGPT v0.2 start to analysis...")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# Gepetto query_model Method
def query_model(query, cb, max_tokens=2500):
    """
    向 gpt-3.5-turbo 发送查询的函数。
    :param query: The request to send to gpt-3.5-turbo
    :param cb: Tu function to which the response will be passed to.
    """
    try:
        if PROD_NAME == "Gemini":
            # 构建带有 role 信息的消息
            messages = [
                {"role": "user", "parts": [{"text": query}]}
            ]
            response = client.models.generate_content(
                model=MODEL,
                contents=messages,
            )
            # 处理 Gemini 的响应格式
            ida_kernwin.execute_sync(
                functools.partial(cb, response=response.text), 
                ida_kernwin.MFF_WRITE
            )
        else:
            # OpenAI 格式保持不变
            response = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "user", "content": query}
                ]
            )
            ida_kernwin.execute_sync(
                functools.partial(cb, response=response.choices[0].message.content), 
                ida_kernwin.MFF_WRITE
            )
    except openai.BadRequestError as e:
        # Context length exceeded. Determine the max number of tokens we can ask for and retry.
        m = re.search(r'maximum context length is (\d+) tokens, however you requested \d+ tokens \((\d+) in your '
                      r'prompt;', str(e))
        if not m:
            print(f"{MODEL} could not complete the request: {str(e)}")
            return
        (hard_limit, prompt_tokens) = (int(m.group(1)), int(m.group(2)))
        max_tokens = hard_limit - prompt_tokens
        if max_tokens >= 750:
            print(f"{PLUGIN_NAME}-Warning: Context length too long! Try reducing tokens to {max_tokens}...")
            print("Request to %s sent retried..."%(MODEL))
            query_model(query, cb, max_tokens)
        else:
            print(f"Unfortunately, this function is too large to be analyzed using {PROD_NAME}-{MODEL} API. @WPeace")
    except openai.OpenAIError as e:
        if "That model is currently overloaded with other requests" in str(e) or "Request timed out" in str(e):
            print(f"{PROD_NAME}-{MODEL} API 繁忙，请稍后重试或检查代理。@WPeace")
        elif "Cannot connect to proxy" in str(e):
            print("代理出现问题，请稍后重试或检查代理。@WPeace")
        else:
            print(f"OpenAI server could not complete the request: {str(e)}")
    except Exception as e:
        print(f"General exception encountered while running the query: {str(e)}")


# Gepetto query_model_async Method
def query_model_async(query, cb, time):
    """
    创建线程调用 query_model 函数。
    :param query: The request to send to gpt-3.5-turbo
    :param cb: Tu function to which the response will be passed to.
    :param time: whether it is a retry.
    """
    if time == 0:
        if ZH_CN:
            print(f"正在发送 {PROD_NAME}:{MODEL} API 请求，完成后将输出提示。@WPeace")
        else:
            print(f"Sending {PROD_NAME}-{MODEL} API request, will output a prompt when completed. @WPeace")
        print("Request to %s sent..."%(MODEL))
    else:
        if ZH_CN:
            print(f"正在重新发送 {PROD_NAME}-{MODEL} API 请求。@WPeace")
        else:
            print(f"Resending {PROD_NAME}-{MODEL} API request. @WPeace")
    t = threading.Thread(target=query_model, args=[query, cb])
    t.start()


# Gepetto comment_callback Method
def comment_callback(address, view, response, cmtFlag, printFlag):
    """
    在对应地址处设置注释的回调函数。
    :param address: The address of the function to comment
    :param view: A handle to the decompiler window
    :param response: The comment to add
    """
    # Add the response as a comment in IDA.
    # 通过参数控制不同形式添加注释
    if cmtFlag == 0:
        idc.set_func_cmt(address, response, 0)
    elif cmtFlag == 1:
        idc.set_cmt(address, response, 1)
    # Refresh the window so the comment is displayed properly
    if view:
        view.refresh_view(False)
    print("%s query finished!"%(MODEL))
    if printFlag == 0:
        if ZH_CN:
            print("%s:Explain 完成分析，已对函数 %s 进行注释。@WPeace" %(PLUGIN_NAME, idc.get_func_name(address)))
        else:
            print("%s:Explain finished analyzing, function %s has been commented. @WPeace" %(PLUGIN_NAME, idc.get_func_name(address)))
    elif printFlag == 1:
        if ZH_CN:
            print("%s:Python 完成分析，已在函数末尾地址 %s 汇编处进行注释。@WPeace"%(PLUGIN_NAME, hex(address)))
        else:
            print("%s:Python finished parsing, commented at assembly at address %s at end of function. @WPeace" %(PLUGIN_NAME, hex(address)))
    elif printFlag == 2:
        if ZH_CN:
            print("%s:VulnFinder 完成分析，已对函数 %s 进行注释。@WPeace" %(PLUGIN_NAME, idc.get_func_name(address)))
        else:
            print("%s: VulnFinder finished analyzing, function %s has been annotated. @WPeace" %(PLUGIN_NAME, idc.get_func_name(address)))
    elif printFlag == 3:
        if ZH_CN:
            print("%s:ExpCreater 完成分析，已对函数 %s 进行注释。@WPeace" %(PLUGIN_NAME, idc.get_func_name(address)))
        else:
            print("%s:ExpCreater finished analyzing, commented on function %s. @WPeace" %(PLUGIN_NAME, idc.get_func_name(address)))


# Gepetto rename_callback Method
def rename_callback(address, view, response, retries=0):
    """
    重命名函数变量的回调函数。
    :param address: The address of the function to work on
    :param view: A handle to the decompiler window
    :param response: The response from gpt-3.5-turbo
    :param retries: The number of times that we received invalid JSON
    """
    j = re.search(r"\{[^}]*?\}", response)
    if not j:
        if retries >= 3:  # Give up obtaining the JSON after 3 times.
            print(f"{PROD_NAME}-{MODEL} API has no valid response, please try again later. @WPeace")
            return
        print(f"Cannot extract valid JSON from the response. Asking the model to fix it...")
        query_model_async("The JSON document provided in this response is invalid. Can you fix it?\n" + response,
                          functools.partial(rename_callback,
                                            address=address,
                                            view=view,
                                            retries=retries + 1), 
                                            1)
        return
    try:
        names = json.loads(j.group(0))
    except json.decoder.JSONDecodeError:
        if retries >= 3:  # Give up fixing the JSON after 3 times.
            print(f"{PROD_NAME}-{MODEL} API has no valid response, please try again later. @WPeace")
            return
        print(f"The JSON document returned is invalid. Asking the model to fix it...")
        query_model_async("Please fix the following JSON document:\n" + j.group(0),
                          functools.partial(rename_callback,
                                            address=address,
                                            view=view,
                                            retries=retries + 1), 
                                            1)
        return
    # The rename function needs the start address of the function
    function_addr = idaapi.get_func(address).start_ea
    replaced = []
    for n in names:
        if ida_hexrays.rename_lvar(function_addr, n, names[n]):
            replaced.append(n)

    # Update possible names left in the function comment
    comment = idc.get_func_cmt(address, 0)
    if comment and len(replaced) > 0:
        for n in replaced:
            comment = re.sub(r'\b%s\b' % n, names[n], comment)
        idc.set_func_cmt(address, comment, 0)
    # Refresh the window to show the new names
    if view:
        view.refresh_view(True)
    print("%s query finished!"%(MODEL))
    if ZH_CN:
        print(f"{PLUGIN_NAME}:RenameVariable 完成分析，已重命名{len(replaced)}个变量。@WPeace")
    else:
        print(f"{PLUGIN_NAME}:RenameVariable Completed analysis, renamed {len(replaced)} variables. @WPeace")


# 获取函数注释
def getFuncComment(address):
    cmt = idc.get_func_cmt(address, 0)
    if not cmt:
        cmt = idc.get_func_cmt(address, 1)
    return cmt


# 获取地址注释
def getAddrComment(address):
    cmt = idc.get_cmt(address, 0)
    if not cmt:
        cmt = idc.get_cmt(address, 1)
    return cmt


# Add context menu actions
class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.explain_action_name, "%s/"%(PLUGIN_NAME))
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.rename_action_name, "%s/"%(PLUGIN_NAME))
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.python_action_name, "%s/"%(PLUGIN_NAME))
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.vulnFinder_action_name, "%s/"%(PLUGIN_NAME))
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.expPython_action_name, "%s/"%(PLUGIN_NAME))


class myplugin_WPeChatGPT(idaapi.plugin_t):
    autoWPeGPT_action_name = "%s:Auto-WPeGPT"%(PLUGIN_NAME)
    autoWPeGPT_menu_path = "Edit/%s/Auto-WPeGPT/Auto-WPeGPT v0.2"%(PLUGIN_NAME)
    explain_action_name = "%s:Explain_Function"%(PLUGIN_NAME)
    explain_menu_path = "Edit/%s/函数分析"%(PLUGIN_NAME)
    rename_action_name = "%s:Rename_Function"%(PLUGIN_NAME)
    rename_menu_path = "Edit/%s/重命名函数变量"%(PLUGIN_NAME)
    python_action_name = "%s:Python_Function"%(PLUGIN_NAME)
    python_menu_path = "Edit/%s/Python还原此函数"%(PLUGIN_NAME)
    vulnFinder_action_name = "%s:VulnFinder_Function"%(PLUGIN_NAME)
    vulnFinder_menu_path = "Edit/%s/二进制漏洞查找"%(PLUGIN_NAME)
    expPython_action_name = "%s:VulnPython_Function"%(PLUGIN_NAME)
    expPython_menu_path = "Edit/%s/尝试生成Exploit"%(PLUGIN_NAME)
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ''
    comment = "%s Plugin for IDA"%(PLUGIN_NAME)
    help = "Find more information at https://github.com/wpeace-hch"
    menu = None
    flags = 0
    def init(self):
        # Check whether the decompiler is available
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP
        if ZH_CN:
            # create Auto-WPeGPT action
            autoWPeGPT_action = idaapi.action_desc_t(self.autoWPeGPT_action_name,
                                                  '二进制文件自动化分析 v0.2',
                                                  autoHandler(),
                                                  "",
                                                  "使用 %s 对二进制文件进行自动化分析"%(MODEL),
                                                  199)
            idaapi.register_action(autoWPeGPT_action)
            idaapi.attach_action_to_menu(self.autoWPeGPT_menu_path, self.autoWPeGPT_action_name, idaapi.SETMENU_APP)
            # Function explaining action
            explain_action = idaapi.action_desc_t(self.explain_action_name,
                                                  '函数分析',
                                                  ExplainHandler(),
                                                  "Ctrl+Alt+G",
                                                  "使用 %s 分析当前函数"%(MODEL),
                                                  199)
            idaapi.register_action(explain_action)
            idaapi.attach_action_to_menu(self.explain_menu_path, self.explain_action_name, idaapi.SETMENU_APP)
            # Variable renaming action
            rename_action = idaapi.action_desc_t(self.rename_action_name,
                                                 '重命名函数变量',
                                                 RenameHandler(),
                                                 "Ctrl+Alt+R",
                                                 "使用 %s 重命名当前函数的变量"%(MODEL),
                                                 199)
            idaapi.register_action(rename_action)
            idaapi.attach_action_to_menu(self.rename_menu_path, self.rename_action_name, idaapi.SETMENU_APP)
            # python function action
            python_action = idaapi.action_desc_t(self.python_action_name,
                                                 'Python还原此函数',
                                                 PythonHandler(),
                                                 "",
                                                 "使用 %s 分析当前函数并用python3还原"%(MODEL),
                                                 199)
            idaapi.register_action(python_action)
            idaapi.attach_action_to_menu(self.python_menu_path, self.python_action_name, idaapi.SETMENU_APP)
            # find vulnerabilty action
            vulnFinder_action = idaapi.action_desc_t(self.vulnFinder_action_name,
                                                  '二进制漏洞查找',
                                                  FindVulnHandler(),
                                                  "Ctrl+Alt+E",
                                                  "使用 %s 在当前函数中查找漏洞"%(MODEL),
                                                  199)
            idaapi.register_action(vulnFinder_action)
            idaapi.attach_action_to_menu(self.vulnFinder_menu_path, self.vulnFinder_action_name, idaapi.SETMENU_APP)
            # create exploit action
            expPython_action = idaapi.action_desc_t(self.expPython_action_name,
                                                  '尝试生成Exploit',
                                                  expCreateHandler(),
                                                  "",
                                                  "使用 %s 尝试对漏洞函数生成EXP"%(MODEL),
                                                  199)
            idaapi.register_action(expPython_action)
            idaapi.attach_action_to_menu(self.expPython_menu_path, self.expPython_action_name, idaapi.SETMENU_APP)
            # Register context menu actions
            self.menu = ContextMenuHooks()
            self.menu.hook()
            print("Auto-WPeGPT v0.2 is ready.")
            print("%s v2.6 works fine! :)@WPeace\n"%(PLUGIN_NAME))
        else:
            # create Auto-WPeGPT action
            autoWPeGPT_action = idaapi.action_desc_t(self.autoWPeGPT_action_name,
                                                  'Automated analysis v0.2',
                                                  autoHandler(),
                                                  "",
                                                  "使用 %s 对二进制文件进行自动化分析"%(MODEL),
                                                  199)
            idaapi.register_action(autoWPeGPT_action)
            idaapi.attach_action_to_menu(self.autoWPeGPT_menu_path, self.autoWPeGPT_action_name, idaapi.SETMENU_APP)
            # Function explaining action
            explain_action = idaapi.action_desc_t(self.explain_action_name,
                                                  'Function analysis',
                                                  ExplainHandler(),
                                                  "Ctrl+Alt+G",
                                                  "使用 %s 分析当前函数"%(MODEL),
                                                  199)
            idaapi.register_action(explain_action)
            idaapi.attach_action_to_menu(self.explain_menu_path, self.explain_action_name, idaapi.SETMENU_APP)
            # Variable renaming action
            rename_action = idaapi.action_desc_t(self.rename_action_name,
                                                 'Rename function variables',
                                                 RenameHandler(),
                                                 "Ctrl+Alt+R",
                                                 "使用 %s 重命名当前函数的变量"%(MODEL),
                                                 199)
            idaapi.register_action(rename_action)
            idaapi.attach_action_to_menu(self.rename_menu_path, self.rename_action_name, idaapi.SETMENU_APP)
            # python function action
            python_action = idaapi.action_desc_t(self.python_action_name,
                                                 'Python restores this function',
                                                 PythonHandler(),
                                                 "",
                                                 "使用 %s 分析当前函数并用python3还原"%(MODEL),
                                                 199)
            idaapi.register_action(python_action)
            idaapi.attach_action_to_menu(self.python_menu_path, self.python_action_name, idaapi.SETMENU_APP)
            # find vulnerabilty action
            vulnFinder_action = idaapi.action_desc_t(self.vulnFinder_action_name,
                                                  'Vulnerability finding',
                                                  FindVulnHandler(),
                                                  "Ctrl+Alt+E",
                                                  "使用 %s 在当前函数中查找漏洞"%(MODEL),
                                                  199)
            idaapi.register_action(vulnFinder_action)
            idaapi.attach_action_to_menu(self.vulnFinder_menu_path, self.vulnFinder_action_name, idaapi.SETMENU_APP)
            # create exploit action
            expPython_action = idaapi.action_desc_t(self.expPython_action_name,
                                                  'Try to generate Exploit',
                                                  expCreateHandler(),
                                                  "",
                                                  "使用 %s 尝试对漏洞函数生成EXP"%(MODEL),
                                                  199)
            idaapi.register_action(expPython_action)
            idaapi.attach_action_to_menu(self.expPython_menu_path, self.expPython_action_name, idaapi.SETMENU_APP)
            # Register context menu actions
            self.menu = ContextMenuHooks()
            self.menu.hook()
            print("Auto-WPeGPT v0.2 is ready.")
            print("%s v2.6 works fine! :)@WPeace\n"%(PLUGIN_NAME))
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        idaapi.detach_action_from_menu(self.autoWPeGPT_menu_path, self.autoWPeGPT_action_name)
        idaapi.detach_action_from_menu(self.explain_menu_path, self.explain_action_name)
        idaapi.detach_action_from_menu(self.rename_menu_path, self.rename_action_name)
        idaapi.detach_action_from_menu(self.python_menu_path, self.python_action_name)
        idaapi.detach_action_from_menu(self.vulnFinder_menu_path, self.vulnFinder_action_name)
        idaapi.detach_action_from_menu(self.expPython_menu_path, self.expPython_action_name)
        if self.menu:
            self.menu.unhook()
        return


def PLUGIN_ENTRY():
    global model_api_key
    if model_api_key == "ENTER_API_KEY_HERE":
        model_api_key = os.getenv("model_api_key")
        if not model_api_key:
            print("未找到 API_KEY，请在脚本中填写 model_api_key! :(@WPeace")
            raise ValueError("No valid OpenAI API key found!")
    return type(f"myplugin_{PLUGIN_NAME}", (myplugin_WPeChatGPT, ), dict())()