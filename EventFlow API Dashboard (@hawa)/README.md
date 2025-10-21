# EventFlow API Dashboard
By @hawa

This was a very basic challenge. We were provided [`index.html`](files/index.html). It is an unobfuscated HTML file with some JavaScript functionality.

It seems you were supposed to interact with the file in order for it to give you the flag if you did all kinds of things in your browser-storage. Instead we read the source-code and find that the flag is encoded and in 4 fragments. Each fragment can be retrieved by calling `getF[1-4]()`.

Some of the alerts hint at the encoding being base64 and rotated 13 characters:

```javascript
var msg = 'API Response from /internal:\n\nStatus: 200\n\nData:\n{\n  "config": "internal_config_loaded",\n  "fragment_1": "' + frag + '",\n  "encoding": "base64+rot13",\n  "note": "Fragment 1 of 4 found"\n}\n\nFRAGMENT 1: ' + frag;
```

Luckily, the `index.html` has a function for `rot13`. So simply pasting this into the browser-console gave the flag:

```javascript
rot13(atob(getF1()))+rot13(atob(getF2()))+rot13(atob(getF3()))+rot13(atob(getF4()))
```

Yields output: `h1dd3n_4p1_3ndp01nt5_f0und`