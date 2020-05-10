---
layout: post
title: A quick glimpse on Windows hooking libraries
modified: 2015-02-25
tags: [hooking]
---

Hooking a program is usually done because one of two reasons: you either want to change the behavior of it, or you want to analyze what it is doing (what functions does it call, which parameters does it call with, etc).

Knowing your purpose is the first step in choosing the right library for your project. In this post I am going to share some thoughts about the following libraries: <a href="http://research.microsoft.com/en-us/projects/detours/" target="_blank">Microsoft Detours</a>, <a href="http://www.nektra.com/products/deviare-api-hook-windows/" target="_blank">Nektra Deviare</a> (+ <a href="http://www.nektra.com/products/deviare-api-hook-windows/deviare-in-process/In-Process" target="_blank">In-Process</a>), <a href="http://easyhook.codeplex.com/" target="_blank">EasyHook</a> and <a href="https://github.com/glmcdona/FunctionHacker" target="_blank">FunctionHacker</a>.

## Hooking in general

<small>_Disclaimer: This post doesn't want to be a comprehensive comparison or anything like that and its statements can be inaccurate. Think about this more like as random thoughts about the subject._</small>

Strictly speaking the basic functionality of function hooking is "only" about redirecting a (typically Windows API) function into an another custom function which usually calls the original function somehow in the end.

This can be done by simply rewriting some function pointers or injecting some jumping code into the prologue of the real function or <a href="http://en.wikipedia.org/wiki/Hooking" target="_blank">any of numerous methods</a>. The most fundamental problem with hooking is that you probably cannot create an universal solution which is stable enough, because hooking often can be very fragile.

This is where the hooking libraries are come into the picture. Most solutions are claiming that they solve the problem in a stable manner, for example there are gossips that Microsoft recompiled Windows once and inserted some NOPs into functions just to make sure that Detours can inject the required jumping payload into the prologue of every API functions.

Although the stability of this basic functionality is important, usually these libraries does not stop here and provide a lot of other useful features. This comparison page about <a href="http://blog.nektra.com/main/2008/12/16/a-comparison-of-deviare-and-easyhook/" target="_blank">Deviare vs. EasyHook</a> gives a good overview about what can be done.

Library | Remote communication
--- | ---
Microsoft Detours | <i class="glyphicon glyphicon-remove" style="color:red; margin-right:10px"></i>Local only
Nektra Deviare In-Process | <i class="glyphicon glyphicon-remove" style="color:red; margin-right:10px"></i>Local only
Nektra Deviare API Hook | <i class="glyphicon glyphicon-ok" style="color:green; margin-right:10px"></i>COM
EasyHook | <i class="glyphicon glyphicon-ok" style="color:green; margin-right:10px"></i>.NET Remoting
FunctionHacker | <i class="glyphicon glyphicon-ok" style="color:green; margin-right:10px"></i>Direct read / write memory

### Heading 3

#### Heading 4

##### Heading 5

###### Heading 6

### Body text

Lorem ipsum dolor sit amet, test link adipiscing elit. **This is strong**. Nullam dignissim convallis est. Quisque aliquam.

![Smithsonian Image]({{ site.url }}/images/3953273590_704e3899d5_m.jpg)
{: .image-right}

*This is emphasized*. Donec faucibus. Nunc iaculis suscipit dui. 53 = 125. Water is H<sub>2</sub>O. Nam sit amet sem. Aliquam libero nisi, imperdiet at, tincidunt nec, gravida vehicula, nisl. The New York Times <cite>(That’s a citation)</cite>. <u>Underline</u>. Maecenas ornare tortor. Donec sed tellus eget sapien fringilla nonummy. Mauris a ante. Suspendisse quam sem, consequat at, commodo vitae, feugiat in, nunc. Morbi imperdiet augue quis tellus.

HTML and <abbr title="cascading stylesheets">CSS<abbr> are our tools. Mauris a ante. Suspendisse quam sem, consequat at, commodo vitae, feugiat in, nunc. Morbi imperdiet augue quis tellus. Praesent mattis, massa quis luctus fermentum, turpis mi volutpat justo, eu volutpat enim diam eget metus.

### Blockquotes

> Lorem ipsum dolor sit amet, test link adipiscing elit. Nullam dignissim convallis est. Quisque aliquam.

## List Types

### Ordered Lists

1. Item one
   1. sub item one
   2. sub item two
   3. sub item three
2. Item two

### Unordered Lists

* Item one
* Item two
* Item three

## Tables

| Header1 | Header2 | Header3 |
|:--------|:-------:|--------:|
| cell1   | cell2   | cell3   |
| cell4   | cell5   | cell6   |
|----
| cell1   | cell2   | cell3   |
| cell4   | cell5   | cell6   |
|=====
| Foot1   | Foot2   | Foot3
{: rules="groups"}

## Code Snippets

Syntax highlighting via Pygments

{% highlight css %}
#container {
  float: left;
  margin: 0 -240px 0 0;
  width: 100%;
}
{% endhighlight %}

Non Pygments code example

    <div id="awesome">
        <p>This is great isn't it?</p>
    </div>

## Buttons

Make any link standout more when applying the `.btn` class.

{% highlight html %}
<a href="#" class="btn btn-success">Success Button</a>
{% endhighlight %}

<div markdown="0"><a href="#" class="btn">Primary Button</a></div>
<div markdown="0"><a href="#" class="btn btn-success">Success Button</a></div>
<div markdown="0"><a href="#" class="btn btn-warning">Warning Button</a></div>
<div markdown="0"><a href="#" class="btn btn-danger">Danger Button</a></div>
<div markdown="0"><a href="#" class="btn btn-info">Info Button</a></div>
