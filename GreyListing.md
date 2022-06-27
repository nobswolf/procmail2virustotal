# Introduction #

GreyListing is something between WhiteListing (you define who may send you email) and BlackListing (you define who is not allowed to send you email). GreyListing says "I am not ready for you, try later". This is completely fine according to the email-standard. But lots of spammers are not capable of this protocol. They will never try again. And even if they do: Other systems like spamassassin gain about 5 Minutes more time to learn from other messages.

I personally use PostGrey because I use PostFix. But this is only my configuration. Just have a look for yourself.
