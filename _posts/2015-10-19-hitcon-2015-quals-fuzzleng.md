---
layout: post
title: "HITCON 2015 Quals: Fuzzleng"
modified: 2015-10-19
tags: hitcon hitcon2015quals
---
*This challenge was solved by one of my teammates, gym and me and the write up was written by gym.*

In this challange we were provided with a flag.puzzle data file and a x86_64 binary called encrypt. After loading the binary into IDA we can see that it "encrypts" a file with a XOR key (received as command line argument) but in an unusual manner. First, it splits the input into 20 equally sized blocks and each block is XORed with the same byte. In the case of the flag file these blocks are 57 bytes long (except the last one).
 
First, we decoded the first block with all the possible keys and printed the output to check if there was any plain text output or known file header. Scrolling throught the results we spot a PNG header thus we realised that the encoded file was a PNG image.
 
After this, we made a regex for all the possible PNG headers and brute forced all blocks and searched the output for these headers. This way we managed to decrypt the first, second and the last blocks.
 
The next step was to find a structure in the png image bytes that we could use to verify if the brute forced data is correct. In the PNG file format before each scanline there is a filter byte with the possible values 0-4. The PNG header told us that the image size is 912x912 and color mode is 0x3 with the bit depth of 1. This meant that a scanline is 114 (912/8) bytes long so each 115th byte (starting with the first) had to be less than four (it turned out fast it should be always the value 0).
 
So we bruteforced the following blocks inflated the compressed data and checked against the above mentioned property. This way we succesfully decoded the 4th block, however the rest of the block resulted with many false positives.
 
So we dumped all the uncompressed image data that passed the check into bitmap images and manually selected the correct one (we could automatize this, but it could be checked very easily manually too as the QR code is started to take form line by line).

The xor keys were: `101, 48, 86, 195, 120, 255, 75, 191, 247, 71, 55, 227, 111, 83, 38, 76, 37, 244, 209, 27`

With this method we managed to decode the rest of the image, which was a QR code for the flag:
{% highlight text %}
hitcon{qrencode -s 16 -o flag.png -I H --foreground 8F77B5 --background 8F77B4}
{% endhighlight %}

Our bruteforcer code was (C#):

{% highlight csharp %}
static byte[] Deflate(byte[] compressedData)
{
    var msOut = new MemoryStream();
    try
    {
        using (var deflate = new DeflateStream(new MemoryStream(compressedData), CompressionMode.Decompress))
        {
            while (true)
            {
                var c = deflate.ReadByte();
                if (c < 0)
                    break;
                msOut.WriteByte((byte)c);
            }
        }
    }
    catch { }
    return msOut.ToArray();
}
 
static void PuzzLeng()
{
    var rawImageData = File.ReadAllBytes(@"flag.puzzle").Skip(0x60).Take(1025 - 2 - 4).ToArray();

    var strideLen = 1 + 912 / 8;
    var validLen = 912 * strideLen;

    for (int bf = 0; bf < 256; bf++)
    {
        var imgData = rawImageData.ToArray();

        int currIdx = 0;
        for (var i = 0; i < 18; i++)
            imgData[currIdx++] ^= 48;

        for (var i = 0; i < 57; i++)
            imgData[currIdx++] ^= 86;

        for (var i = 0; i < 57; i++)
            imgData[currIdx++] ^= 195;

        for (var i = 0; i < 57; i++)
            imgData[currIdx++] ^= (byte)bf;
            
        // ...

        var decompr = Deflate(imgData.Take(currIdx).Concat(Enumerable.Repeat((byte)0x00, 1000)).ToArray());
        if(decompr.Length == 0) continue;

        var bmp = new Bitmap(912, 912);
        for (int y = 0; y < 912; y++)
        {
            var strideStart = y * strideLen;
            if (strideStart + strideLen > decompr.Length)
                break;

            if (decompr[strideStart] != 0)
                break;

            for (int x = 0; x < 912; x++)
            {
                var b = decompr[strideStart + 1 + x / 8];
                var bitVal = ((b >> (7 - (x % 8))) & 1) == 1;
                bmp.SetPixel(x, y, bitVal  Color.Red : Color.Black);
            }
        }
       
        bmp.Save(@"puzzleng\img_" + currIdx + "_" + bf + ".png", ImageFormat.Png);
    }
}
{% endhighlight %}