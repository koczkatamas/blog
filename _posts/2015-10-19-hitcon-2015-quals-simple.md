---
layout: post
title: "HITCON 2015 Quals: Simple"
modified: 2015-10-19
tags: hitcon hitcon2015quals
---
*This challenge was solved by and the write up was written by one of my teammates, aljasPOD.* 

Register with a single letter user & single letter password. The resulting json:
{% highlight json %}
{"username":"a","password":"a","db":"hitcon-ctf"}
{% endhighlight %}

Which is encoded with AES-CFB, in 16 byte blocks:

{% highlight text %}
{"username":"a",
"password":"a","
db":"hitcon-ctf"
}
{% endhighlight %}

and set as the cookie with the IV.

XORing something to the cyphertext will xor the same to the related cleartext & fuck up the next block.

If we change the 3rd block from
{% highlight text %}
db":"hitcon-ctf"
{% endhighlight %}
to
{% highlight text %}
admin":true}
{% endhighlight %}

(by xoring the bytes 49-60 and cut off the rest of the cookie), we will have what is needed to become admin.

Our code was (Delphi):

{% highlight delphi %}
unit Unit3;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls;

type
  TForm3 = class(TForm)
    Button1: TButton;
    Edit1: TEdit;
    Edit2: TEdit;
    procedure Button1Click(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form3: TForm3;

implementation

uses IdTCPClient;

{$R *.dfm}

function EncodeURIComponent(const ASrc: string): UTF8String;
const
  HexMap: UTF8String = '0123456789ABCDEF';

      function IsSafeChar(ch: Integer): Boolean;
      begin
        if (ch >= 48) and (ch <= 57) then Result := True    // 0-9
        else if (ch >= 65) and (ch <= 90) then Result := True  // A-Z
        else if (ch >= 97) and (ch <= 122) then Result := True  // a-z
        else if (ch = 33) then Result := True // !
        else if (ch >= 39) and (ch <= 42) then Result := True // '()*
        else if (ch >= 45) and (ch <= 46) then Result := True // -.
        else if (ch = 95) then Result := True // _
        else if (ch = 126) then Result := True // ~
        else Result := False;
      end;
var
  I, J: Integer;
  ASrcUTF8: UTF8String;
begin
  Result := '';    {Do not Localize}

  ASrcUTF8 := UTF8Encode(ASrc);
    // UTF8Encode call not strictly necessary but
    // prevents implicit conversion warning

  I := 1; J := 1;
  SetLength(Result, Length(ASrcUTF8) * 3); // space to %xx encode every byte
  while I <= Length(ASrcUTF8) do
  begin
    if IsSafeChar(Ord(ASrcUTF8[I])) then
    begin
      Result[J] := ASrcUTF8[I];
      Inc(J);
    end
    else if ASrcUTF8[I] = ' ' then
    begin
      Result[J] := '+';
      Inc(J);
    end
    else
    begin
      Result[J] := '%';
      Result[J+1] := HexMap[(Ord(ASrcUTF8[I]) shr 4) + 1];
      Result[J+2] := HexMap[(Ord(ASrcUTF8[I]) and 15) + 1];
      Inc(J,3);
    end;
    Inc(I);
  end;

   SetLength(Result, J-1);
end;

function DoPost(user: string; pass: string): string;
var C: TIdTCPClient;
    s,s2: string;
    chunked: Boolean;
    ctL: Boolean;
    rem: integer;
    buff: Array of Byte;
    AData: string;
begin
rem := 0;
SetLength(buff,1024);
Result := '';
C := TIdTCPClient.Create;
C.Host := '52.69.244.164';
C.Port := 51913;
C.Connect;
AData := 'username=' + EncodeURIComponent(user) + '&password=' + EncodeURIComponent(pass);
C.IOHandler.WriteLn('POST / HTTP/1.1');
C.IOHandler.WriteLn('Host: 52.69.244.164:51913');
C.IOHandler.WriteLn('Content-Length: ' + IntToStr(Length(AData)));
C.IOHandler.WriteLn('Content-Type: application/x-www-form-urlencoded');
C.IOHandler.WriteLn('');
C.IOHandler.Write(AData);
s := 'a';
chunked := False;
ctl := False;
s2 := '';
while s <> '' do
   begin
   s := C.IOHandler.ReadLn;
   if copy(s,1,12) = 'Set-Cookie: ' then
      begin
      if pos(' auth=',s) > 0 then
         begin
         Result := copy(s,pos(' auth=',s) + 6);
         Result := copy(Result,1,pos(';',Result) - 1);
         end;
      end;
   if copy(s,1,16) = 'Content-Length: ' then
      begin
      ctL := True;
      rem := StrToInt(copy(s,17));
      end;
   if s = 'Transfer-Encoding: chunked' then
      chunked := True;
   s2 := s2 + s;
   end;
s := 'a';
s2 := '';
if not chunked then
   begin
   if ctl then
      begin
      s2 := C.IOHandler.ReadString(rem);
      end
      else
      begin
      while C.IOHandler.Readable(1000) do
         begin
         s := C.IOHandler.ReadLn;
         s2 := s2 + s;
         end;
      end;
   end
   else
   begin
   while True do
     begin
     s := C.IOHandler.ReadLn;
     if s = '0' then
        Break;
     rem := StrToInt('$' + s);
     s2 := s2 + C.IOHandler.ReadString(rem);
     s := C.IOHandler.ReadLn;
     end;
   end;
C.Free;
//ShowMessage(Result);
//Result := s2;
end;

function DoGet(cookie: string): string;
var C: TIdTCPClient;
    s,s2: string;
    chunked: Boolean;
    ctL: Boolean;
    rem: integer;
    buff: Array of Byte;
  x: Integer;
    cck: string;
begin
cck := '';
while cookie <> '' do
   begin
   cck := cck + '%' + copy(cookie,1,2);
   cookie := copy(cookie,3);
   end;
rem := 0;
SetLength(buff,1024);
Result := '';
C := TIdTCPClient.Create;
C.Host := '52.69.244.164';
C.Port := 51913;
C.Connect;
C.IOHandler.WriteLn('GET / HTTP/1.1');
C.IOHandler.WriteLn('Host: 52.69.244.164:51913');
C.IOHandler.WriteLn('Cookie: auth=' + cck);
C.IOHandler.WriteLn('Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8');
C.IOHandler.WriteLn('');
s := 'a';
chunked := False;
ctl := False;
s2 := '';
while s <> '' do
   begin
   s := C.IOHandler.ReadLn;
   if copy(s,1,16) = 'Content-Length: ' then
      begin
      ctL := True;
      rem := StrToInt(copy(s,17));
      end;
   if s = 'Transfer-Encoding: chunked' then
      chunked := True;
   s2 := s2 + s;
   end;
s := 'a';
s2 := '';
if not chunked then
   begin
   if ctl then
      begin
      s2 := C.IOHandler.ReadString(rem);
      end
      else
      begin
      while C.IOHandler.Readable(1000) do
         begin
         s := C.IOHandler.ReadLn;
         s2 := s2 + s;
         end;
      end;
   end
   else
   begin
   while True do
     begin
     s := C.IOHandler.ReadLn;
     if s = '0' then
        Break;
     rem := StrToInt('$' + s);
     s2 := s2 + C.IOHandler.ReadString(rem);
     s := C.IOHandler.ReadLn;
     end;
   end;
C.Free;
Result := s2;
end;

procedure TForm3.Button1Click(Sender: TObject);
var s1, s2, s3, s4: string;
    bs: array[1..16] of byte;
    x: Integer;
    ss: string;
    SL: TStringList;
    y: Integer;
    sss: string;
begin
s4 := DoPost('a','b');
Edit1.Text := s4;
s1 := '';
while s4 <> '' do
   begin
   if s4[1] = '%' then
      begin
      s1 := s1 + copy(s4,2,2);
      s4 := copy(s4,4);
      end
      else
      begin
      s1 := s1 + IntToHex(ord(s4[1]),2);
      s4 := copy(s4,2);
      end;
   end;
Edit2.Text := s1;
ShowMessage(DoGet(s1));
s2 := 'db":"hitcon-ctf"';
s3 := 'admin":true}    ';
for x := 48 to 63 do
    begin
    bs[x - 47] := StrToInt('$' + copy(s1,x * 2 + 1,2));
    end;
for x := 1 to 16 do
    bs[x] := bs[x] xor (ord(s2[x]) xor ord(s3[x]));
s4 := copy(s1,1,96);
for x := 1 to 12 do
    s4 := s4 + IntToHex(bs[x],2);
ShowMessage(doget(s4));
end;

end.
{% endhighlight %}