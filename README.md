# brida_custom
Brida Custom Plugin to help transparently dec and enc data during testing

# Notice
this plugin uses the exported function (encrypt and decrypt) of your Brida script, if you want to use, pls implement it yourself.

It's `encrypt` whole request body when you hit `go`, and `decrypt` response body when receiving a response.

And it's UTF-8 friendly.
