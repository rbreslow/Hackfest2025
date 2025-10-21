# 01
We don't have the challenge description, but the most relevant part is that we are told that there are 3 docker services running in a network and then we are given a link to one of them.

On the page, there is a text box that can be used to ping services. It quickly becomes apparent that this works by giving the string to the `ping` command and thus we can exploit this by providing `'';`. Then we can get some more info by running `''; ls` where we see that there is a text file called `flag.txt`. 

So, to get the first flag we run `''; cat flag.txt` and get: `HF-IRHrQUuVQzMyHiEJCjRuyPwtRPSOSWkH`.