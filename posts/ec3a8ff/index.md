# JQCTF2025 Customize Virtual Machine Official Writeup


大意是用输入的 50 位 flag 解密 vm 的 handler 然后需要正确输出对应字符串，函数地址和长度表在二进制文件里直接给了，可以直接提取。

注意到前 15 个是全部解密，后 35 个少解密一个字节，不难想到常规函数的最后一个字节都是 retn 指令 0xC3，利用这个特性可以解出前 15 byte 的 flag 并且获得 15 个函数样本，不难发现所有被加密的 Handler 的模式都是大致相同的，可以用这些样本预测后续的函数。

后续 35 字节需要爆破，根据 flag 格式字符范围在 36 个左右，先判断解密结果有没有包含非法指令（用 pwntools 反汇编就是不出现 bad 或 byte），如果没有的话直接把解密结果和之前的 15 个样本喂给 AI 判断相似程度即可。

&lt;!--more--&gt;

测试用的 gpt-4o-mini，构造的 prompt 如下：

&gt; You are now a professional assembly code analyst. There are 20 example code snippets here(separated by =====). You need to determine whether the given code is similar to these example codes. Only needs to be similar to any one of the example code snippets. We consider two code segments to be similar if both code segments perform similar functions. Example code: {sample}, given code: {TestCode}. If similar respond True otherwise False, do not include any additional information.

exp 如下，脸黑网慢的话大概要跑个 15 分钟左右。

```python
from pwn import *
from openai import OpenAI

#Function address table 0x47C0
addr = [4592, 4704, 4816, 4928, 5008, 5136, 5248, 5344, 5376, 5504, 5520, 5632, 5776, 5856, 5936, 6032, 6160, 6192, 6240, 6352, 6464, 6576, 6672, 6800, 6912, 6928, 7056, 7152, 7184, 7296, 7328, 7424, 7536, 7568, 7648, 7664, 7776, 7872, 7968, 8080, 8176, 8256, 8336, 8464, 8560, 8688, 8800, 8832, 8960, 9072]
# Function length table 0x46E0
lens = [109, 109, 108, 78, 119, 98, 84, 22, 117, 13, 97, 138, 76, 80, 94, 113, 18, 42, 110, 107, 99, 93, 120, 109, 16, 128, 83, 24, 112, 29, 87, 112, 24, 75, 13, 105, 86, 84, 101, 91, 77, 79, 113, 88, 121, 102, 19, 122, 110, 98]

sample = &#34;&#34;
flag = &#34;&#34;

# Use Byte retn to get first 15 byte of flag and sample functions.
for j in range(15):
    with open(&#34;customVM&#34;, &#39;rb&#39;) as f:
        data = bytearray(f.read())[addr[j]:addr[j]&#43;lens[j]]
    print(data)
    key = data[-1]^0xc3
    flag &#43;= chr(key)
    c = b&#34;&#34;
    for _ in data:
        c &#43;= (_^key).to_bytes(1, byteorder=&#34;little&#34;)
    assembly_code = disasm(c, arch=&#39;amd64&#39;, os=&#39;linux&#39;)
    sample &#43;= assembly_code&#43;&#34;\n&#34;
    sample &#43;= &#34;============\n&#34;

print(&#34;First 15 byte: &#34;, flag)

# Use AI to Predict the rest
for j in range(15, 50):
    table = &#34;0123456789abcdefghijklmnopqrstuvwxyz_&#34;

    for ii in table:
        got = False
        i = ord(ii)
        c = b&#34;&#34;
        with open(&#34;customVM&#34;, &#39;rb&#39;) as f:
            machine_code = bytearray(f.read())[addr[j]:addr[j]&#43;lens[j]-1]
        
        for _ in machine_code:
            c &#43;= (_^i).to_bytes(1, byteorder=&#34;little&#34;)
      
        TestCode = disasm(c, arch=&#39;amd64&#39;, os=&#39;linux&#39;)
        runnable = True
        for lines in TestCode.split(&#39;\n&#39;):
            if &#34;byte&#34; in lines or &#34;(bad)&#34; in lines: # Not Runnable Code
                runnable = False
                break
        if runnable:
            print(&#34;TESTING: &#34;, ii)
            print(TestCode)
            print(&#34;============&#34;)
            prompt = f&#34;You are now a professional assembly code analyst. There are 20 example code snippets here(separated by =====). You need to determine whether the given code is similar to these example codes. Only needs to be similar to any one of the example code snippets. We consider two code segments to be similar if both code segments perform similar functions. Example code: {sample}, given code: {TestCode}. If similar respond True otherwise False, do not include any additional information.&#34;
            
            client = OpenAI(
                base_url=&#39;xxxx&#39;,
                api_key=&#39;xxxx&#39;,
            )
            chat_completion = client.chat.completions.create(
                messages=[
                    {
                        &#34;role&#34;: &#34;user&#34;,
                        &#34;content&#34;: prompt,
                    }
                ],
                model=&#34;gpt-4o-mini&#34;,
            )
            print(chat_completion.choices[0].message.content)
            if &#34;True&#34; in chat_completion.choices[0].message.content or &#34;true&#34; in chat_completion.choices[0].message.content:
                got = True
                flag &#43;= ii
                print(f&#34;Got flag[{ii}]: {flag}&#34;)
                break
    
    if not got:
        print(&#34;WARN: TRY AGAIN ON &#34;, j)

print(flag)
```



---

> Author:   
> URL: https://www.sh1no.icu/posts/ec3a8ff/  

