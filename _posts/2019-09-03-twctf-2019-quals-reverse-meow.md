---
layout: post
title: "TokyoWesterns CTF 5th 2019: Reverse - meow"
modified: 2019-09-03
tags: twctf, twctf2019quals, reverse
---

We got two files with the challenge:
* `meow.n`, running `file` command on it said: `NekoVM bytecode (418 global symbols, 323 global fields, 35212 bytecode ops)`
* `flag_enc.png` which was a seemingly encrypted PNG image:
![alt]({{ site.url }}/images/twctf2019quals/flag_enc.png)

I googled `NekoVM` which lead me to https://nekovm.org/ which said:

> Neko is a high-level dynamically typed programming language. It can be used as an embedded scripting language. It has been designed to provide a common runtime for several different languages. Learning and using Neko is very easy. You can easily extend the language with C libraries. You can also write generators from your own language to Neko and then use the Neko Runtime to compile, run, and access existing libraries.

Okay, something, something, yet again some unknown byte code. I googled for disassembler, but it turned out the official toolchain includes one: https://nekovm.org/doc/tools/#dumping-bytecode , so I run

```
nekoc -d meow.n
```

and I got a 620k `meow.dump` file. Uhh, that's a lot of code. I searched for `xor` in the dump as I usually do if I start working with a lot of code, and I found a few interesting strings around the xoring code lines like `get_pixel`, `set_pixel`, `setSeed`, `random_set_seed`, `file_open`, `file_read`, `AccInt 13337`.

I also found some usage information: `Usage: meow INPUT OUTPUT`.

As the bytecode was new to me, I googled some description on what these "operators" mean, and I found this [Neko Bytecode Explained](https://repl.it/@king1600/Neko-Bytecode-Explained) page which would be a really good resource I think.

BUT I thought: okay, so it reads a PNG and generates some random, uses some magic seeds and contants like `13337` and writes an another PNG. I could probably find out the exact algorithm from the byte code **statically** but that **would take ages**, so let's analyze it **dynamically** instead.

So I encrypted a full black and white 768x768 PNG (just like the original). Actually I did it both twice and got the exact same result (for the same color), and I got the inverse for the other, so I could be sure that the algorithm kind of static and there is no random stored in the encrypted file.

![alt]({{ site.url }}/images/twctf2019quals/black.png) -> ![alt]({{ site.url }}/images/twctf2019quals/black_enc.png)
![alt]({{ site.url }}/images/twctf2019quals/white.png) -> ![alt]({{ site.url }}/images/twctf2019quals/white_enc.png)

Okay, the result was similar to our encrypted flag, so I simply **xored** the `black_enc.png` with `flag_enc.png` and I got this:

![alt]({{ site.url }}/images/twctf2019quals/flag.png)

Wow that is almost a readable `flag`, but it looks like the columns were mixed.

Then I encrypted images with unique columns and decrypted with my method and result seemed consistent:

![alt]({{ site.url }}/images/twctf2019quals/color.png) -> ![alt]({{ site.url }}/images/twctf2019quals/color_dec.png)
![alt]({{ site.url }}/images/twctf2019quals/unique.png) -> ![alt]({{ site.url }}/images/twctf2019quals/unique_enc_dec.png)

So I simply tried to reorganize the columns in the same order as it changed on my test file and I got the original image with the flag actually:

![alt]({{ site.url }}/images/twctf2019quals/flag_dec.png)

So the flag was:

{% highlight text %}
TWCTF{t1ny_XXE_st1ll_ex1sts_everywhere}
{% endhighlight %}

And this was my solver code (C#):

{% highlight csharp %} 
static void Meow()
{
    var baseDir = @"G:\Dropbox\prg_shared\twctf19\challs\meow\";

    void Decrypt(string fn, int[] order)
    {
        var bmp = new Bitmap($"{baseDir}{fn}.png");
        var key = new Bitmap($"{baseDir}black_enc.png");
        var res = new Bitmap(bmp.Width, bmp.Height);

        for (var y = 0; y < bmp.Height; y++)
            for (var x = 0; x < bmp.Width; x++)
            {
                var c = bmp.GetPixel(x, y);
                var kc = key.GetPixel(x, y);
                res.SetPixel(order[x], y, Color.FromArgb(c.R ^ kc.R, c.G ^ kc.G, c.B ^ kc.B));
            }

        res.Save($"{baseDir}{fn}_dec.png", ImageFormat.Png);
    }

    void GenUnique()
    {
        var res = new Bitmap(768, 768);

        for (var y = 0; y < res.Height; y++)
            for (var x = 0; x < res.Width; x++)
                res.SetPixel(x, y, Color.FromArgb(x / 256 * 96, x % 256, 0));

        res.Save($"{baseDir}unique.png", ImageFormat.Png);
    }

    int[] GetUniqueOrder(string fn)
    {
        var result = new int[768];
        var bmp = new Bitmap($"{baseDir}{fn}.png");
        for (int i = 0; i < 768; i++)
        {
            var c = bmp.GetPixel(i, 0);
            result[i] = c.R / 96 * 256 + c.G;
        }
        return result;
    }

    //GenUnique();            
    var orderTest = GetUniqueOrder("unique");
    var orderTestOk = orderTest.Select((x, i) => x == i).All(x => x);
    var orderReal = GetUniqueOrder("unique_enc_dec");
    Decrypt("flag_enc", orderReal);
}
{% endhighlight %}