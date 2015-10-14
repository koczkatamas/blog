---
layout: post
title: "ASIS 2015 Finals: MBTI"
modified: 2015-10-14
tags: asis asis2015finals forensics
---

*This challenge was solved by and the write up was written by one of my teammates, AKG and me* 

First of all we found the mbti page (mbti.asis-ctf.ir) in the pcap file (ClientHello sent the host name to support SNI - Server Name Identification), which was a simple [Myers–Briggs Type Indicator test](https://en.wikipedia.org/wiki/Myers%E2%80%93Briggs_Type_Indicator) (each question with 4 answers).

We found out that the text in the question depends on the previous answer, and the length of the texts differ.

After this we collected the data lengths from the pcap file (with scapy) and the questions lengths for each question-previous answer pairs (manually) and used some statistics to find out what the answers the candidate provided.

We had to install the [scapy-ssl_tls plugin](https://github.com/tintinweb/scapy-ssl_tls).

With this command we converted the pcap content to a more easily parsable text document:
{% highlight python %}
open('mbti.txt','w').write('\n'.join([x.command() for x in rdpcap('mbti.pcap')]));
{% endhighlight %}

And then filtered for the response packet lengths (in C# this time):

{% highlight csharp %}
var vals = File.ReadLines(@"mbti.txt").Where(x => x.Contains("dst='192.168.110.13'") && x.Contains("content_type=23")).
    Select(x => Regex.Match(x, @"TLSRecord\(length=(\d+)").Groups[1].Value).Where(x => !String.IsNullOrWhiteSpace(x)).Select(x => int.Parse(x)).ToArray();

var valsRev = File.ReadLines(@"mbti.txt").Where(x => x.Contains("src='192.168.110.13'") && x.Contains("content_type=23")).
    Select(x => Regex.Match(x, @"TLSRecord\(length=(\d+)").Groups[1].Value).Where(x => !String.IsNullOrWhiteSpace(x)).Select(x => int.Parse(x)).ToArray();

var data = Enumerable.Range(0, vals.Length).Select(idx => new { idx, requestLen = valsRev[idx], responseLen = vals[idx] }).ToArray();
var respLens = new[] { 1635 }.Concat(data.Where(x => x.requestLen == 628).Select(x => x.responseLen).Take(24).ToArray());

var respMin = respLens.Min();
var respMax = respLens.Max();
var respPerc = respLens.Select(x => (double)(x - respMin) / (respMax - respMin)).ToArray();

var questions = File.ReadAllLines(@"mbti_path.txt").Select(x => Regex.Match(x, @"Q(\d+)A(\d+) = (.*)")).
    Select(m => new QuestionData { Q = int.Parse(m.Groups[1].Value), A = int.Parse(m.Groups[2].Value), Text = m.Groups[3].Value }).ToArray();

foreach (var q in questions)
    q.Text = q.Q + " " + q.Text;

var textMin = questions.Min(x => x.Text.Length);
var textMax = questions.Max(x => x.Text.Length);

foreach (var q in questions)
{
    q.Len = q.Text.Length;
    q.Perc = (double)(q.Len - textMin) / (textMax - textMin) / 0.795;
}

var searcher = questions.GroupBy(x => x.Q).Select((x, i) => new { Q = x.First().Q, good = respPerc[i], choices = x.ToArray() }).ToArray();
var searcherStr = String.Join("\r\n\r\n", searcher.Select(x => "Question #" + x.Q + " => " + x.good.ToString("0.0000") + "\r\n" + String.Join("\r\n", x.choices.Select(y => "[ ] " + y.ToString()))));
var answer = String.Join("", searcher.Select(x => x.choices.OrderBy(y => Math.Abs(y.Perc - x.good)).First().A));
{% endhighlight %}

This file contains the 100 questions and to path to reach them: [mbti_path.txt]({{ site.url }}/images/asis2015finals/mbti_path.txt)

This generated the template of following output:

 - Question #0 is the answer to the age question (your name does not matter)
 - The number after the question if the relative length of the response found in the pcap
 - The "P" values of the answers are the calculated relative lengths of that answer
 - The smaller the difference between the two numbers the more likely that that answer was choosen

{% highlight text %}
Answer = 1101131103330121020113013

Question #0 => 0,3651
[ ] Q:00 A:0 L:093 P:0,5221 = You feel unsatisfied if you know the answer to a problem, but do not completely understand it
[X] Q:00 A:1 L:073 P:0,3639 = You prefer to act immediately rather than speculate about various options
[ ] Q:00 A:2 L:038 P:0,0870 = You are very consistent in your habits
[ ] Q:00 A:3 L:063 P:0,2848 = You are a person somewhat reserved and distant in communication

Question #1 => 0,7698
[ ] Q:01 A:0 L:076 P:0,3876 = You usually place yourself nearer to the side than in the center of the room
[X] Q:01 A:1 L:124 P:0,7674 = You are mainly interested in things other than human, You prefer good books or even a good Computer rather than good friends
[ ] Q:01 A:2 L:123 P:0,7595 = You think that everyone's views should be respected regardless of whether they are supported by facts or not or even by you
[ ] Q:01 A:3 L:077 P:0,3956 = You often get so lost in thoughts that you ignore or forget your surroundings

Question #2 => 0,0476
[X] Q:02 A:0 L:033 P:0,0475 = It's difficult to get you excited
[ ] Q:02 A:1 L:131 P:0,8228 = You are almost never late for your appointments, and get angry when other people are late or try to make excuses for their lateness
[ ] Q:02 A:2 L:134 P:0,8465 = You tend to be unbiased even if this might endanger your good relations with people, but try to stay calm when people nagging about it
[ ] Q:02 A:3 L:066 P:0,3085 = Interesting book or video game is often better than a social event

Question #3 => 0,0000
[ ] Q:03 A:0 L:151 P:0,9810 = You always prefer inclined to experiment than to follow familiar approaches, in this way you can experince something that maybe no one could experince!
[X] Q:03 A:1 L:027 P:0,0000 = You feel at ease in a crowd
[ ] Q:03 A:2 L:098 P:0,5617 = You find it difficult to speak loudly in public places and think that people find it very annoying
[ ] Q:03 A:3 L:071 P:0,3481 = You are inclined to rely more on improvisation than on careful planning

Question #4 => 0,7937
[ ] Q:04 A:0 L:068 P:0,3244 = You are always looking for opportunities and don't like to miss them
[X] Q:04 A:1 L:127 P:0,7911 = You prefer to spend your leisure time alone or relaxing in a tranquil family atmosphere, but always being home bothers you alot
[ ] Q:04 A:2 L:112 P:0,6724 = You find it easy to stay relaxed and focused even when there is some pressure and could work under that oressure
[ ] Q:04 A:3 L:053 P:0,2057 = Your desk, workbench etc. is usually neat and orderly

Question #5 => 1,0000
[ ] Q:05 A:0 L:128 P:0,7990 = If your friend is sad about something, you are more likely to offer emotional support than suggest ways to deal with the problem
[ ] Q:05 A:1 L:100 P:0,5775 = If you go to the gym or the library or the park, you find a place by yourself and focus on your work
[ ] Q:05 A:2 L:047 P:0,1582 = You enjoy having a wide circle of acquaintances
[X] Q:05 A:3 L:153 P:0,9968 = You frequently and easily express your feelings and emotions, it doesn't matter with new people or not, the moment you start, there is no way to stop you

Question #6 => 0,7222
[ ] Q:06 A:0 L:067 P:0,3164 = You find it difficult to talk about your feelings with other people
[X] Q:06 A:1 L:118 P:0,7199 = When considering a situation you pay more attention to the current situation and less to a possible sequence of events
[ ] Q:06 A:2 L:035 P:0,0633 = You value justice higher than mercy
[ ] Q:06 A:3 L:069 P:0,3323 = It is easy for you to communicate in social situations and new people

Question #7 => 0,2302
[ ] Q:07 A:0 L:089 P:0,4905 = You are product-oriented and want to get the job done and not interested only in progress
[X] Q:07 A:1 L:056 P:0,2294 = It is in your nature to assume responsibility for others
[ ] Q:07 A:2 L:088 P:0,4826 = Being able to develop a plan and stick to it is the most important part of every project
[ ] Q:07 A:3 L:078 P:0,4035 = Strict observance of the established rules is likely to prevent a good outcome

Question #8 => 0,5952
[X] Q:08 A:0 L:102 P:0,5933 = Deadlines seem to you to be of relative, rather than absolute, importance and you never scared of them
[ ] Q:08 A:1 L:091 P:0,5063 = You know how to put every minute of your time to good purpose and feelling great after that
[ ] Q:08 A:2 L:054 P:0,2136 = You like to be engaged in an active and fast-paced job
[ ] Q:08 A:3 L:144 P:0,9256 = You are usually the first to react to a sudden event: the telephone ringing or unexpected question, that doesn't matter, you will always answer!

Question #9 => 0,2698
[ ] Q:09 A:0 L:135 P:0,8544 = You rapidly get involved in social life at new workplaces and can work with new people specially when they let you share your new ideas
[ ] Q:09 A:1 L:040 P:0,1028 = You tend to sympathize with other people
[ ] Q:09 A:2 L:044 P:0,1345 = You could easily affected by strong emotions
[X] Q:09 A:3 L:060 P:0,2611 = You often think about humankind and its destiny in your life

Question #10 => 0,7222
[ ] Q:10 A:0 L:057 P:0,2373 = You are good at speculating about all the various options
[ ] Q:10 A:1 L:109 P:0,6487 = You have good control over your desires and temptations and could leave out what you want in speciall moments
[ ] Q:10 A:2 L:106 P:0,6250 = You feel involved when watching TV soaps, maybe cry with them and you get really upset or happy after them
[X] Q:10 A:3 L:117 P:0,7120 = If you could choose your in-flight neighbor, you would prefer someone silent to someone who is interesting to talk to

Question #11 => 0,5873
[ ] Q:11 A:0 L:080 P:0,4193 = You are more interested in a general idea than in the details of its realization
[ ] Q:11 A:1 L:095 P:0,5380 = You tend to rely on your experience rather than on theoretical alternatives, very experimental?
[ ] Q:11 A:2 L:052 P:0,1978 = Objective criticism is always useful in any activity
[X] Q:11 A:3 L:100 P:0,5775 = You respond with aggression when someone acts aggressively towards you and thet can change your mood

Question #12 => 0,9286
[X] Q:12 A:0 L:143 P:0,9177 = The process of searching for solution is more important to you than the solution itself, and always try to describe the seraching process first
[ ] Q:12 A:1 L:146 P:0,9414 = The more people with whom you speak, the better you feel, at work or in the family, you are always the person people come to talk about everything
[ ] Q:12 A:2 L:172 P:1,1471 = Winning a debate is more important to you than making sure no one gets upset during that debate, people thinks you don't care about their feelings when it comes to debates!
[ ] Q:12 A:3 L:143 P:0,9177 = You prefer meeting in small groups to interaction with lots of people, because of thet you rarley have new friends and try to avoid new friends

Question #13 => 0,6270
[ ] Q:13 A:0 L:086 P:0,4668 = When solving a problem you would rather follow a familiar approach than seek a new one
[X] Q:13 A:1 L:105 P:0,6171 = You often feel as if you have to justify yourself to other people and wait for them ti take what you said
[ ] Q:13 A:2 L:075 P:0,3797 = You don't usually initiate conversations and wait for other people to start
[ ] Q:13 A:3 L:097 P:0,5538 = If someone doesn't respond to your e-mail quickly, you start worrying if you said something wrong

Question #14 => 0,2302
[ ] Q:14 A:0 L:048 P:0,1661 = You think that almost everything can be analyzed
[ ] Q:14 A:1 L:085 P:0,4588 = You try to respond to your e-mails as soon as possible and cannot stand a messy inbox
[X] Q:14 A:2 L:055 P:0,2215 = You feel a constant need for something new in your life
[ ] Q:14 A:3 L:083 P:0,4430 = You like to keep a check on how things are progressing, and that make you confident

Question #15 => 0,5397
[ ] Q:15 A:0 L:099 P:0,5696 = It does not take you much time to start getting involved in social activities at your new workplace
[X] Q:15 A:1 L:094 P:0,5300 = You are strongly touched by the stories about people's troubles and don't like to be with them
[ ] Q:15 A:2 L:132 P:0,8307 = Your decisions are based more on the feelings of a moment than on the careful planning, maybe you regret what you decided after that
[ ] Q:15 A:3 L:092 P:0,5142 = Your work style is closer to random energy spikes than to a methodical or organized approach

Question #16 => 0,0159
[X] Q:16 A:0 L:028 P:0,0079 = You often do jobs in a hurry
[ ] Q:16 A:1 L:079 P:0,4114 = It's essential for you to try things with your own hands and get new experinces
[ ] Q:16 A:2 L:159 P:1,0443 = You prefer to isolate yourself from outside noises and stay at home, even when you are at home you are lonely at your room and don't like to be with family too
[ ] Q:16 A:3 L:087 P:0,4747 = You readily help people while asking nothing in return, mostly you are happy after that

Question #17 => 0,2778
[ ] Q:17 A:0 L:046 P:0,1503 = Your home and work environments are quite tidy
[ ] Q:17 A:1 L:116 P:0,7041 = Before answering a question, you always prefer to take the time to form an answer in your head and after that answer
[X] Q:17 A:2 L:061 P:0,2690 = You often feel like there are very few things that excite you
[ ] Q:17 A:3 L:082 P:0,4351 = Being adaptable is more important to you than being organized in work or education

Question #18 => 0,0873
[ ] Q:18 A:0 L:138 P:0,8781 = After prolonged socializing you will feel you need to get away and being alone, walking alone or being alone at home makes you feel better
[X] Q:18 A:1 L:037 P:0,0791 = You trust reason rather than feelings
[ ] Q:18 A:2 L:108 P:0,6408 = You take pleasure in putting things in order and think that being organized is what you need and others need
[ ] Q:18 A:3 L:114 P:0,6883 = You usually plan your actions in advance and stick to the plan, and it bothers when you can't manage all the plans

Question #19 => 0,8492
[ ] Q:19 A:0 L:050 P:0,1820 = Your actions are frequently influenced by emotions
[X] Q:19 A:1 L:133 P:0,8386 = You spend your leisure time actively socializing with a group of people, attending parties, shopping and taking with new people, etc.
[ ] Q:19 A:2 L:064 P:0,2927 = You easily see the general principle behind specific occurrences
[ ] Q:19 A:3 L:059 P:0,2532 = You easily understand new theoretical principles in no time

Question #20 => 0,0238
[ ] Q:20 A:0 L:130 P:0,8148 = You believe being consistent and stable is one of your best personal qualities and other people must like it or at least admire it
[X] Q:20 A:1 L:029 P:0,0158 = You see deadlines as elastics
[ ] Q:20 A:2 L:120 P:0,7357 = You could easily empathize with the concerns of other people and like other people would be more concerned about you too
[ ] Q:20 A:3 L:045 P:0,1424 = A thirst for adventure is close to your heart

Question #21 => 0,0794
[ ] Q:21 A:0 L:154 P:1,0047 = As a rule, current preoccupations worry you more than your future plans and what comes next, the most pressure is always what it is now that bothering you
[ ] Q:21 A:1 L:032 P:0,0396 = You believe any feeling is valid
[ ] Q:21 A:2 L:104 P:0,6092 = You often spend time thinking of how things could be improved and try to make things improved after that
[X] Q:21 A:3 L:036 P:0,0712 = You avoid being bound by obligations

Question #22 => 0,5079
[X] Q:22 A:0 L:090 P:0,4984 = You really get pleasure from solitary walks and often palns to do that especially in rain!
[ ] Q:22 A:1 L:062 P:0,2769 = You easily perceive various ways in which events could develop
[ ] Q:22 A:2 L:074 P:0,3718 = Often you prefer to read a book than go to a party and other pucliv places
[ ] Q:22 A:3 L:110 P:0,6566 = You get bored if you have to read theoretical books and never finish them completely, but get most of the book

Question #23 => 0,3492
[ ] Q:23 A:0 L:096 P:0,5459 = You do not mind being at the center of attention in a gathering or in work place or even at home
[X] Q:23 A:1 L:070 P:0,3402 = You willingly involve yourself in matters which engage your sympathies
[ ] Q:23 A:2 L:043 P:0,1266 = You do your best to complete a task on time
[ ] Q:23 A:3 L:170 P:1,1313 = You enjoy switching back and forth between tasks. In fact, You grow restless if you have to focus on only one task for too long at a time, and so you welcome some variety

Question #24 => 0,1984
[ ] Q:24 A:0 L:146 P:0,9414 = You often contemplate about the complexity of life and how hard it is, but always think that something could happen and could make the hard easier
[ ] Q:24 A:1 L:186 P:1,2579 = You prefer to work on one task at a time and to finish it before moving on to the next thing. Your efficiency goes down if you have to multitask, and so you find interruptions disruptive
[ ] Q:24 A:2 L:042 P:0,1187 = You try to stand firmly by your principles
[X] Q:24 A:3 L:051 P:0,1899 = You consider the scientific approach to be the best
{% endhighlight %}

As you can see in the most cases the answer was obvious, but we wasn't sure about question #12 (there were 2 possibilities with the same 0.9177% relative length) and of course we didn't know the answer to the last question. 

This left us with 2 * 4 = 8 possibilities, which we tried out by hand:

{% highlight text %}
First number is the answer to the question #12, second number is the answer to the last question.

00 - ASIS{d9df3ae429c782e3323e3f9ae2a5d931} - incorrect
01 - ASIS{7c435d15918d509985b6889201af96ac} - incorrect
02 - ASIS{f795bf214782f87ca9ebb4d3131a267d} - incorrect
03 - ASIS{6a2affd40db76ee918cb45df76ccc23f} - incorrect
30 - ASIS{bd72d3d93f7028afe3d986d8ed11ee93} - incorrect
31 - ASIS{a83a6b53c481a8cfea0277db30040edd} - incorrect
33 - ASIS{95b468a9d13ee4ebb5cfd19ead0fbc8a} - incorrect
32 - ASIS{01d3c6afe8046b28eef7ac98a19cae85} - good flag!
{% endhighlight %}

So the right combination was: 11011311033331210201130132, which gave us the right flag:

{% highlight text %}
ASIS{01d3c6afe8046b28eef7ac98a19cae85}
{% endhighlight %}