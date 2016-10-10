---
layout: post
title: "HITCON 2016 Quals: Handcrafted pyc (rev50)"
modified: 2016-10-10
tags: hitcon, hitcon2016quals, reverse
---

Saved payload as pyc with this script:

{% highlight python %}
import marshal, zlib, base64

open('code.pyc','wb').write('03f30d0a5a8cbc52'.decode('hex') + zlib.decompress(base64.b64decode('eJyNVktv...kLHmeCBQ==')))
{% endhighlight %}

Disassembled the pyc file with uncompyle:

{% highlight text %}
kt@ubuntu:~/ctf/hitcon2016$ uncompyle6 code.pyc
# Python 2.7 (decompiled from Python 2.7)
# Embedded file name: <string>
# Compiled at: 2013-12-26 21:06:50


def main--- This code section failed: ---

   1       0    LOAD_GLOBAL       'chr'
           3    LOAD_CONST        108
           6    CALL_FUNCTION_1   ''
           9    LOAD_GLOBAL       'chr'
          12    LOAD_CONST        108
          15    CALL_FUNCTION_1   ''
          18    LOAD_GLOBAL       'chr'
          21    LOAD_CONST        97
...
{% endhighlight %}

Simulated the string creation with this C# code:

{% highlight csharp %}
static void HandcraftedPyc()
{
    // Call me a Python virtual machine! I can interpret Python bytecodes!!!
    var cmds = File.ReadAllLines(@"disas.txt").Select(x => Regex.Match(x, @"(.*?)\s+(.*)").Groups.OfType<Group>().Skip(1).Select(g => g.Value).ToArray()).ToArray();
    var stack = new Stack<string>();
    foreach (var cmd in cmds)
    {
        if (cmd[0] == "LOAD_GLOBAL" || cmd[0] == "LOAD_CONST")
            stack.Push(cmd[1]);
        else if (cmd[0] == "CALL_FUNCTION_1")
        {
            var arg = stack.Pop();
            var func = stack.Pop();
            if (func == "'chr'")
                stack.Push("" + (char)int.Parse(arg));
            else
                Debugger.Break();
        }
        else if (cmd[0] == "ROT_TWO")
        {
            var arg1 = stack.Pop();
            var arg2 = stack.Pop();
            stack.Push(arg1);
            stack.Push(arg2);
        }
        else if (cmd[0] == "BINARY_ADD")
        {
            var arg1 = stack.Pop();
            var arg2 = stack.Pop();
            stack.Push(arg2 + arg1);
        }
        else
            Debugger.Break();
    }
}
{% endhighlight %}

At the end the stack contains one variable, the 'decrypted' string. The first code block created the string "Call me a Python virtual machine! I can interpret Python bytecodes!!!", while the second code block created the flag:

{% highlight text %}
hitcon{Now you can compile and run Python bytecode in your brain!}
{% endhighlight %}