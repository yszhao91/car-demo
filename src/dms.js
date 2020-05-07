(function () {
  var hex_md5 = null;
  //md5方法
  (function () {
    /*
     * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
     * Digest Algorithm, as defined in RFC 1321.
     * Version 2.2 Copyright (C) Paul Johnston 1999 - 2009
     * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
     * Distributed under the BSD License
     * See http://pajhome.org.uk/crypt/md5 for more info.
     */

    /*
     * Configurable variables. You may need to tweak these to be compatible with
     * the server-side, but the defaults work in most cases.
     */
    var hexcase = 0; /* hex output format. 0 - lowercase; 1 - uppercase        */
    var b64pad = ""; /* base-64 pad character. "=" for strict RFC compliance   */

    /*
     * These are the functions you'll usually want to call
     * They take string arguments and return either hex or base-64 encoded strings
     */
    hex_md5 = function (s) {
      return rstr2hex(rstr_md5(str2rstr_utf8(s)));
    }

    function b64_md5(s) {
      return rstr2b64(rstr_md5(str2rstr_utf8(s)));
    }

    function any_md5(s, e) {
      return rstr2any(rstr_md5(str2rstr_utf8(s)), e);
    }

    function hex_hmac_md5(k, d) {
      return rstr2hex(rstr_hmac_md5(str2rstr_utf8(k), str2rstr_utf8(d)));
    }

    function b64_hmac_md5(k, d) {
      return rstr2b64(rstr_hmac_md5(str2rstr_utf8(k), str2rstr_utf8(d)));
    }

    function any_hmac_md5(k, d, e) {
      return rstr2any(rstr_hmac_md5(str2rstr_utf8(k), str2rstr_utf8(d)), e);
    }

    /*
     * Perform a simple self-test to see if the VM is working
     */
    function md5_vm_test() {
      return hex_md5("abc").toLowerCase() == "900150983cd24fb0d6963f7d28e17f72";
    }

    /*
     * Calculate the MD5 of a raw string
     */
    function rstr_md5(s) {
      return binl2rstr(binl_md5(rstr2binl(s), s.length * 8));
    }

    /*
     * Calculate the HMAC-MD5, of a key and some data (raw strings)
     */
    function rstr_hmac_md5(key, data) {
      var bkey = rstr2binl(key);
      if (bkey.length > 16)
        bkey = binl_md5(bkey, key.length * 8);

      var ipad = Array(16),
        opad = Array(16);
      for (var i = 0; i < 16; i++)
      {
        ipad[i] = bkey[i] ^ 0x36363636;
        opad[i] = bkey[i] ^ 0x5C5C5C5C;
      }

      var hash = binl_md5(ipad.concat(rstr2binl(data)), 512 + data.length * 8);
      return binl2rstr(binl_md5(opad.concat(hash), 512 + 128));
    }

    /*
     * Convert a raw string to a hex string
     */
    function rstr2hex(input) {
      try
      {
        hexcase
      } catch (e)
      {
        hexcase = 0;
      }
      var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
      var output = "";
      var x;
      for (var i = 0; i < input.length; i++)
      {
        x = input.charCodeAt(i);
        output += hex_tab.charAt((x >>> 4) & 0x0F) + hex_tab.charAt(x & 0x0F);
      }
      return output;
    }

    /*
     * Convert a raw string to a base-64 string
     */
    function rstr2b64(input) {
      try
      {
        b64pad
      } catch (e)
      {
        b64pad = '';
      }
      var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      var output = "";
      var len = input.length;
      for (var i = 0; i < len; i += 3)
      {
        var triplet = (input.charCodeAt(i) << 16) | (i + 1 < len ? input.charCodeAt(i + 1) << 8 : 0) | (i + 2 < len ? input.charCodeAt(i + 2) : 0);
        for (var j = 0; j < 4; j++)
        {
          if (i * 8 + j * 6 > input.length * 8)
            output += b64pad;
          else
            output += tab.charAt((triplet >>> 6 * (3 - j)) & 0x3F);
        }
      }
      return output;
    }

    /*
     * Convert a raw string to an arbitrary string encoding
     */
    function rstr2any(input, encoding) {
      var divisor = encoding.length;
      var i,
        j,
        q,
        x,
        quotient;

      /* Convert to an array of 16-bit big-endian values, forming the dividend */
      var dividend = Array(Math.ceil(input.length / 2));
      for (i = 0; i < dividend.length; i++)
      {
        dividend[i] = (input.charCodeAt(i * 2) << 8) | input.charCodeAt(i * 2 + 1);
      }

      /*
       * Repeatedly perform a long division. The binary array forms the dividend,
       * the length of the encoding is the divisor. Once computed, the quotient
       * forms the dividend for the next step. All remainders are stored for later
       * use.
       */
      var full_length = Math.ceil(input.length * 8 /
        (Math.log(encoding.length) / Math.log(2)));
      var remainders = Array(full_length);
      for (j = 0; j < full_length; j++)
      {
        quotient = Array();
        x = 0;
        for (i = 0; i < dividend.length; i++)
        {
          x = (x << 16) + dividend[i];
          q = Math.floor(x / divisor);
          x -= q * divisor;
          if (quotient.length > 0 || q > 0)
            quotient[quotient.length] = q;
        }
        remainders[j] = x;
        dividend = quotient;
      }

      /* Convert the remainders to the output string */
      var output = "";
      for (i = remainders.length - 1; i >= 0; i--)
        output += encoding.charAt(remainders[i]);

      return output;
    }

    /*
     * Encode a string as utf-8.
     * For efficiency, this assumes the input is valid utf-16.
     */
    function str2rstr_utf8(input) {
      var output = "";
      var i = -1;
      var x,
        y;

      while (++i < input.length)
      {
        /* Decode utf-16 surrogate pairs */
        x = input.charCodeAt(i);
        y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
        if (0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF)
        {
          x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
          i++;
        }

        /* Encode output as utf-8 */
        if (x <= 0x7F)
          output += String.fromCharCode(x);
        else if (x <= 0x7FF)
          output += String.fromCharCode(0xC0 | ((x >>> 6) & 0x1F),
            0x80 | (x & 0x3F));
        else if (x <= 0xFFFF)
          output += String.fromCharCode(0xE0 | ((x >>> 12) & 0x0F),
            0x80 | ((x >>> 6) & 0x3F),
            0x80 | (x & 0x3F));
        else if (x <= 0x1FFFFF)
          output += String.fromCharCode(0xF0 | ((x >>> 18) & 0x07),
            0x80 | ((x >>> 12) & 0x3F),
            0x80 | ((x >>> 6) & 0x3F),
            0x80 | (x & 0x3F));
      }
      return output;
    }

    /*
     * Encode a string as utf-16
     */
    function str2rstr_utf16le(input) {
      var output = "";
      for (var i = 0; i < input.length; i++)
        output += String.fromCharCode(input.charCodeAt(i) & 0xFF,
          (input.charCodeAt(i) >>> 8) & 0xFF);
      return output;
    }

    function str2rstr_utf16be(input) {
      var output = "";
      for (var i = 0; i < input.length; i++)
        output += String.fromCharCode((input.charCodeAt(i) >>> 8) & 0xFF,
          input.charCodeAt(i) & 0xFF);
      return output;
    }

    /*
     * Convert a raw string to an array of little-endian words
     * Characters >255 have their high-byte silently ignored.
     */
    function rstr2binl(input) {
      var output = Array(input.length >> 2);
      for (var i = 0; i < output.length; i++)
        output[i] = 0;
      for (var i = 0; i < input.length * 8; i += 8)
        output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << (i % 32);
      return output;
    }

    /*
     * Convert an array of little-endian words to a string
     */
    function binl2rstr(input) {
      var output = "";
      for (var i = 0; i < input.length * 32; i += 8)
        output += String.fromCharCode((input[i >> 5] >>> (i % 32)) & 0xFF);
      return output;
    }

    /*
     * Calculate the MD5 of an array of little-endian words, and a bit length.
     */
    function binl_md5(x, len) {
      /* append padding */
      x[len >> 5] |= 0x80 << ((len) % 32);
      x[(((len + 64) >>> 9) << 4) + 14] = len;

      var a = 1732584193;
      var b = -271733879;
      var c = -1732584194;
      var d = 271733878;

      for (var i = 0; i < x.length; i += 16)
      {
        var olda = a;
        var oldb = b;
        var oldc = c;
        var oldd = d;

        a = md5_ff(a, b, c, d, x[i + 0], 7, -680876936);
        d = md5_ff(d, a, b, c, x[i + 1], 12, -389564586);
        c = md5_ff(c, d, a, b, x[i + 2], 17, 606105819);
        b = md5_ff(b, c, d, a, x[i + 3], 22, -1044525330);
        a = md5_ff(a, b, c, d, x[i + 4], 7, -176418897);
        d = md5_ff(d, a, b, c, x[i + 5], 12, 1200080426);
        c = md5_ff(c, d, a, b, x[i + 6], 17, -1473231341);
        b = md5_ff(b, c, d, a, x[i + 7], 22, -45705983);
        a = md5_ff(a, b, c, d, x[i + 8], 7, 1770035416);
        d = md5_ff(d, a, b, c, x[i + 9], 12, -1958414417);
        c = md5_ff(c, d, a, b, x[i + 10], 17, -42063);
        b = md5_ff(b, c, d, a, x[i + 11], 22, -1990404162);
        a = md5_ff(a, b, c, d, x[i + 12], 7, 1804603682);
        d = md5_ff(d, a, b, c, x[i + 13], 12, -40341101);
        c = md5_ff(c, d, a, b, x[i + 14], 17, -1502002290);
        b = md5_ff(b, c, d, a, x[i + 15], 22, 1236535329);

        a = md5_gg(a, b, c, d, x[i + 1], 5, -165796510);
        d = md5_gg(d, a, b, c, x[i + 6], 9, -1069501632);
        c = md5_gg(c, d, a, b, x[i + 11], 14, 643717713);
        b = md5_gg(b, c, d, a, x[i + 0], 20, -373897302);
        a = md5_gg(a, b, c, d, x[i + 5], 5, -701558691);
        d = md5_gg(d, a, b, c, x[i + 10], 9, 38016083);
        c = md5_gg(c, d, a, b, x[i + 15], 14, -660478335);
        b = md5_gg(b, c, d, a, x[i + 4], 20, -405537848);
        a = md5_gg(a, b, c, d, x[i + 9], 5, 568446438);
        d = md5_gg(d, a, b, c, x[i + 14], 9, -1019803690);
        c = md5_gg(c, d, a, b, x[i + 3], 14, -187363961);
        b = md5_gg(b, c, d, a, x[i + 8], 20, 1163531501);
        a = md5_gg(a, b, c, d, x[i + 13], 5, -1444681467);
        d = md5_gg(d, a, b, c, x[i + 2], 9, -51403784);
        c = md5_gg(c, d, a, b, x[i + 7], 14, 1735328473);
        b = md5_gg(b, c, d, a, x[i + 12], 20, -1926607734);

        a = md5_hh(a, b, c, d, x[i + 5], 4, -378558);
        d = md5_hh(d, a, b, c, x[i + 8], 11, -2022574463);
        c = md5_hh(c, d, a, b, x[i + 11], 16, 1839030562);
        b = md5_hh(b, c, d, a, x[i + 14], 23, -35309556);
        a = md5_hh(a, b, c, d, x[i + 1], 4, -1530992060);
        d = md5_hh(d, a, b, c, x[i + 4], 11, 1272893353);
        c = md5_hh(c, d, a, b, x[i + 7], 16, -155497632);
        b = md5_hh(b, c, d, a, x[i + 10], 23, -1094730640);
        a = md5_hh(a, b, c, d, x[i + 13], 4, 681279174);
        d = md5_hh(d, a, b, c, x[i + 0], 11, -358537222);
        c = md5_hh(c, d, a, b, x[i + 3], 16, -722521979);
        b = md5_hh(b, c, d, a, x[i + 6], 23, 76029189);
        a = md5_hh(a, b, c, d, x[i + 9], 4, -640364487);
        d = md5_hh(d, a, b, c, x[i + 12], 11, -421815835);
        c = md5_hh(c, d, a, b, x[i + 15], 16, 530742520);
        b = md5_hh(b, c, d, a, x[i + 2], 23, -995338651);

        a = md5_ii(a, b, c, d, x[i + 0], 6, -198630844);
        d = md5_ii(d, a, b, c, x[i + 7], 10, 1126891415);
        c = md5_ii(c, d, a, b, x[i + 14], 15, -1416354905);
        b = md5_ii(b, c, d, a, x[i + 5], 21, -57434055);
        a = md5_ii(a, b, c, d, x[i + 12], 6, 1700485571);
        d = md5_ii(d, a, b, c, x[i + 3], 10, -1894986606);
        c = md5_ii(c, d, a, b, x[i + 10], 15, -1051523);
        b = md5_ii(b, c, d, a, x[i + 1], 21, -2054922799);
        a = md5_ii(a, b, c, d, x[i + 8], 6, 1873313359);
        d = md5_ii(d, a, b, c, x[i + 15], 10, -30611744);
        c = md5_ii(c, d, a, b, x[i + 6], 15, -1560198380);
        b = md5_ii(b, c, d, a, x[i + 13], 21, 1309151649);
        a = md5_ii(a, b, c, d, x[i + 4], 6, -145523070);
        d = md5_ii(d, a, b, c, x[i + 11], 10, -1120210379);
        c = md5_ii(c, d, a, b, x[i + 2], 15, 718787259);
        b = md5_ii(b, c, d, a, x[i + 9], 21, -343485551);

        a = safe_add(a, olda);
        b = safe_add(b, oldb);
        c = safe_add(c, oldc);
        d = safe_add(d, oldd);
      }
      return Array(a, b, c, d);
    }

    /*
     * These functions implement the four basic operations the algorithm uses.
     */
    function md5_cmn(q, a, b, x, s, t) {
      return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s), b);
    }

    function md5_ff(a, b, c, d, x, s, t) {
      return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
    }

    function md5_gg(a, b, c, d, x, s, t) {
      return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
    }

    function md5_hh(a, b, c, d, x, s, t) {
      return md5_cmn(b ^ c ^ d, a, b, x, s, t);
    }

    function md5_ii(a, b, c, d, x, s, t) {
      return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
    }

    /*
     * Add integers, wrapping at 2^32. This uses 16-bit operations internally
     * to work around bugs in some JS interpreters.
     */
    function safe_add(x, y) {
      var lsw = (x & 0xFFFF) + (y & 0xFFFF);
      var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
      return (msw << 16) | (lsw & 0xFFFF);
    }

    /*
     * Bitwise rotate a 32-bit number to the left.
     */
    function bit_rol(num, cnt) {
      return (num << cnt) | (num >>> (32 - cnt));
    }
  })();


  //json2
  if (typeof JSON !== "object")
  {
    JSON = {};
  }

  (function () {
    "use strict";

    var rx_one = /^[\],:{}\s]*$/;
    var rx_two = /\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4})/g;
    var rx_three = /"[^"\\\n\r]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?/g;
    var rx_four = /(?:^|:|,)(?:\s*\[)+/g;
    var rx_escapable = /[\\"\u0000-\u001f\u007f-\u009f\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g;
    var rx_dangerous = /[\u0000\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g;

    function f(n) {
      // Format integers to have at least two digits.
      return n < 10 ? "0" + n : n;
    }

    function this_value() {
      return this.valueOf();
    }

    if (typeof Date.prototype.toJSON !== "function")
    {

      Date.prototype.toJSON = function () {

        return isFinite(this.valueOf()) ? this.getUTCFullYear() + "-" +
          f(this.getUTCMonth() + 1) + "-" +
          f(this.getUTCDate()) + "T" +
          f(this.getUTCHours()) + ":" +
          f(this.getUTCMinutes()) + ":" +
          f(this.getUTCSeconds()) + "Z" : null;
      };

      Boolean.prototype.toJSON = this_value;
      Number.prototype.toJSON = this_value;
      String.prototype.toJSON = this_value;
    }

    var gap;
    var indent;
    var meta;
    var rep;


    function quote(string) {

      // If the string contains no control characters, no quote characters, and no
      // backslash characters, then we can safely slap some quotes around it.
      // Otherwise we must also replace the offending characters with safe escape
      // sequences.

      rx_escapable.lastIndex = 0;
      return rx_escapable.test(string) ? "\"" + string.replace(rx_escapable, function (a) {
        var c = meta[a];
        return typeof c === "string" ? c : "\\u" + ("0000" + a.charCodeAt(0).toString(16)).slice(-4);
      }) + "\"" : "\"" + string + "\"";
    }


    function str(key, holder) {

      // Produce a string from holder[key].

      var i; // The loop counter.
      var k; // The member key.
      var v; // The member value.
      var length;
      var mind = gap;
      var partial;
      var value = holder[key];

      // If the value has a toJSON method, call it to obtain a replacement value.

      if (value && typeof value === "object" &&
        typeof value.toJSON === "function")
      {
        value = value.toJSON(key);
      }

      // If we were called with a replacer function, then call the replacer to
      // obtain a replacement value.

      if (typeof rep === "function")
      {
        value = rep.call(holder, key, value);
      }

      // What happens next depends on the value's type.

      switch (typeof value)
      {
        case "string":
          return quote(value);

        case "number":

          // JSON numbers must be finite. Encode non-finite numbers as null.

          return isFinite(value) ? String(value) : "null";

        case "boolean":
        case "null":

          // If the value is a boolean or null, convert it to a string. Note:
          // typeof null does not produce "null". The case is included here in
          // the remote chance that this gets fixed someday.

          return String(value);

        // If the type is "object", we might be dealing with an object or an array or
        // null.

        case "object":

          // Due to a specification blunder in ECMAScript, typeof null is "object",
          // so watch out for that case.

          if (!value)
          {
            return "null";
          }

          // Make an array to hold the partial results of stringifying this object value.

          gap += indent;
          partial = [];

          // Is the value an array?

          if (Object.prototype.toString.apply(value) === "[object Array]")
          {

            // The value is an array. Stringify every element. Use null as a placeholder
            // for non-JSON values.

            length = value.length;
            for (i = 0; i < length; i += 1)
            {
              partial[i] = str(i, value) || "null";
            }

            // Join all of the elements together, separated with commas, and wrap them in
            // brackets.

            v = partial.length === 0 ? "[]" : gap ? "[\n" + gap + partial.join(",\n" + gap) + "\n" + mind + "]" : "[" + partial.join(",") + "]";
            gap = mind;
            return v;
          }

          // If the replacer is an array, use it to select the members to be stringified.

          if (rep && typeof rep === "object")
          {
            length = rep.length;
            for (i = 0; i < length; i += 1)
            {
              if (typeof rep[i] === "string")
              {
                k = rep[i];
                v = str(k, value);
                if (v)
                {
                  partial.push(quote(k) + (
                    gap ? ": " : ":"
                  ) + v);
                }
              }
            }
          } else
          {

            // Otherwise, iterate through all of the keys in the object.

            for (k in value)
            {
              if (Object.prototype.hasOwnProperty.call(value, k))
              {
                v = str(k, value);
                if (v)
                {
                  partial.push(quote(k) + (
                    gap ? ": " : ":"
                  ) + v);
                }
              }
            }
          }

          // Join all of the member texts together, separated with commas,
          // and wrap them in braces.

          v = partial.length === 0 ? "{}" : gap ? "{\n" + gap + partial.join(",\n" + gap) + "\n" + mind + "}" : "{" + partial.join(",") + "}";
          gap = mind;
          return v;
      }
    }

    // If the JSON object does not yet have a stringify method, give it one.

    if (typeof JSON.stringify !== "function")
    {
      meta = { // table of character substitutions
        "\b": "\\b",
        "\t": "\\t",
        "\n": "\\n",
        "\f": "\\f",
        "\r": "\\r",
        "\"": "\\\"",
        "\\": "\\\\"
      };
      JSON.stringify = function (value, replacer, space) {

        // The stringify method takes a value and an optional replacer, and an optional
        // space parameter, and returns a JSON text. The replacer can be a function
        // that can replace values, or an array of strings that will select the keys.
        // A default replacer method can be provided. Use of the space parameter can
        // produce text that is more easily readable.

        var i;
        gap = "";
        indent = "";

        // If the space parameter is a number, make an indent string containing that
        // many spaces.

        if (typeof space === "number")
        {
          for (i = 0; i < space; i += 1)
          {
            indent += " ";
          }

          // If the space parameter is a string, it will be used as the indent string.

        } else if (typeof space === "string")
        {
          indent = space;
        }

        // If there is a replacer, it must be a function or an array.
        // Otherwise, throw an error.

        rep = replacer;
        if (replacer && typeof replacer !== "function" &&
          (typeof replacer !== "object" ||
            typeof replacer.length !== "number"))
        {
          throw new Error("JSON.stringify");
        }

        // Make a fake root object containing our value under the key of "".
        // Return the result of stringifying the value.

        return str("", {
          "": value
        });
      };
    }


    // If the JSON object does not yet have a parse method, give it one.

    if (typeof JSON.parse !== "function")
    {
      JSON.parse = function (text, reviver) {

        // The parse method takes a text and an optional reviver function, and returns
        // a JavaScript value if the text is a valid JSON text.

        var j;

        function walk(holder, key) {

          // The walk method is used to recursively walk the resulting structure so
          // that modifications can be made.

          var k;
          var v;
          var value = holder[key];
          if (value && typeof value === "object")
          {
            for (k in value)
            {
              if (Object.prototype.hasOwnProperty.call(value, k))
              {
                v = walk(value, k);
                if (v !== undefined)
                {
                  value[k] = v;
                } else
                {
                  delete value[k];
                }
              }
            }
          }
          return reviver.call(holder, key, value);
        }


        // Parsing happens in four stages. In the first stage, we replace certain
        // Unicode characters with escape sequences. JavaScript handles many characters
        // incorrectly, either silently deleting them, or treating them as line endings.

        text = String(text);
        rx_dangerous.lastIndex = 0;
        if (rx_dangerous.test(text))
        {
          text = text.replace(rx_dangerous, function (a) {
            return "\\u" +
              ("0000" + a.charCodeAt(0).toString(16)).slice(-4);
          });
        }

        // In the second stage, we run the text against regular expressions that look
        // for non-JSON patterns. We are especially concerned with "()" and "new"
        // because they can cause invocation, and "=" because it can cause mutation.
        // But just to be safe, we want to reject all unexpected forms.

        // We split the second stage into 4 regexp operations in order to work around
        // crippling inefficiencies in IE's and Safari's regexp engines. First we
        // replace the JSON backslash pairs with "@" (a non-JSON character). Second, we
        // replace all simple value tokens with "]" characters. Third, we delete all
        // open brackets that follow a colon or comma or that begin the text. Finally,
        // we look to see that the remaining characters are only whitespace or "]" or
        // "," or ":" or "{" or "}". If that is so, then the text is safe for eval.

        if (
          rx_one.test(
            text
              .replace(rx_two, "@")
              .replace(rx_three, "]")
              .replace(rx_four, "")
          )
        )
        {

          // In the third stage we use the eval function to compile the text into a
          // JavaScript structure. The "{" operator is subject to a syntactic ambiguity
          // in JavaScript: it can begin a block or an object literal. We wrap the text
          // in parens to eliminate the ambiguity.

          j = eval("(" + text + ")");

          // In the optional fourth stage, we recursively walk the new structure, passing
          // each name/value pair to a reviver function for possible transformation.

          return (typeof reviver === "function") ? walk({
            "": j
          }, "") : j;
        }

        // If the text is not JSON parseable, then a SyntaxError is thrown.

        throw new SyntaxError("JSON.parse");
      };
    }
  }());


  /**
   * 统计方法类
   * @constructor
   */
  var LcUtil = function () {
    this.init();
  };
  LcUtil.prototype = {
    constructor: LcUtil,
    eventCache: {},
    eventCacheKey: "lcevtcache",
    /**
     * 初始化,默认执行操作
     * @method init
     * @returns {LcUtil}
     */
    init: function () {
      this.env = '';
      this.st = new Date().getTime();
      this.store = ["chifeng", "anshan", "datong", "linfen", "jining", "bengbu", "anqing", "xinyang", "zibo", "xiangyang", "quanzhou", "liuzhou", "nanchong", "yichang", "luohe", "pingxiang", "suizhou", "jiuquan", "shangluo", "dingxi", "yantai", "wuxi", "chengdu", "yuxi", "sanmenxia", "puyang", "kunming", "suzhou", "lvliang", "yuncheng", "jinzhong", "jincheng", "liaocheng", "xining", "xiaogan", "tonghua", "wuzhou", "jiaozuo", "weifang", "taizhou", "nanning", "yueyang", "zhuzhou", "xianyang", "anyang", "guilin", "baoji", "shangrao", "changzhi", "huanggang", "tongliao", "yulin", "yangzhou", "linyi", "suqian", "qiqihaer", "wulumuqi", "lanzhou", "meishan", "rizhao", "taian", "bazhong", "baotou", "changzhou", "fuzhou", "ganzhou", "huaihua", "jinhua", "maanshan", "putian", "qingdao", "xuchang", "yinchuan", "zigong", "shangqiu", "hebi", "guangyuan", "changchun", "wulanchabu", "xuzhou", "wuhan", "haerbin", "eerduosi", "nanchang", "longyan", "changde", "jingdezhen", "deyang", "cangzhou", "tieling", "huaibei", "keshan", "suihua", "zhengzhou", "xinxiang", "foshan", "wuzhong", "huainan", "dongguan", "siping", "quzhou", "qizhou", "guyuan", "heze", "taiyuan", "zhongshan", "huizhou", "zhangzhou", "fuyang", "changsha", "nanyang", "nantong", "nanjing", "qinhuangdao", "tangshan", "shijiazhuang", "baoding", "dalian", "chongqing", "hefei", "xian"];
      this.getType();
      //收集页面自定义事件点击率
      this.putClickSe();
      return this;
    },
    /**
     * [getCookieOptions 获取cookie选项
     * ]
     * @param  {[type]} expires [description]
     * @return {[type]}         [description]
     */
    getCookieOptions: function (expires) {
      var siteDomain = document.domain;
      var matchs = /^(\w*)\.([\w\.]*)$/.exec(siteDomain);
      var options = {
        path: "/"
      }
      if (expires)
      {
        options.expires = expires;
      }
      if (matchs.length > 2)
      {
        siteDomain = matchs[2];
        //options.domain = siteDomain;
      }
      return options;
    },
    /**
     * [setEventCache 设置事件缓存]
     */
    setEventCache: function () {
      var options = this.getCookieOptions();
      this.cookie(this.eventCacheKey, encodeURIComponent(JSON.stringify(this.eventCache)), options);
    },
    /**
     * 根据lc-type发送相应的收集
     * @method getType
     */
    getType: function () {
      // var typeArr = DMS.types;
      for (var j = 0; j < typeArr.length; j++)
      {
        switch (typeArr[j])
        {
          case 'rc':
            //收集正常流量
            this.putRc();
            break;
          case 'pe':
            //收集错误信息
            this.getPageErrInfo();
            break;
          case 'rt':
            //收集页面打开时长
            this.putRt();
            break;
          case 'cl':
            //收集页面点击位置
            this.putCl();
            break;
        }
      }
    },
    /**
     * 增加localStorage
     */
    setLocalStorage: function () {
      var _this = this;
      try
      {
        if (window.localStorage)
        {
          var _md5 = hex_md5(new Date().getTime() + window.navigator.userAgent + parseInt(Math.random() * 100000) + window.location.href);
          window.localStorage.setItem('lctjuid', _md5);
        } else
        {
          _this.noSign = true;
        }
      } catch (ex)
      {
        _this.noSign = true;
      }
    },
    getMd5Sign: function () {
      var _md5 = hex_md5(new Date().getTime() + window.navigator.userAgent + parseInt(Math.random() * 100000) + window.location.href);
      return _md5;
    },
    getUid: function () {
      var lctuid = this.cookie("lctuid");
      var options = this.getCookieOptions(3560);
      if (!lctuid)
      {
        lctuid = this.getMd5Sign();
        this.cookie("lctuid", lctuid, options);
      }
      return lctuid;
    },
    /**
     * 获取localStorage
     */
    getLocalStorage: function () {
      if (window.localStorage)
      {
        var lctjuid = window.localStorage.getItem('lctjuid');
        if (lctjuid)
        {
          return lctjuid;
        } else
        {
          this.setLocalStorage();
          return window.localStorage.getItem('lctjuid');
        }
      } else
      {
        this.noSign = true;
      }
    },
    /**
     * 把uid放入window.name
     */
    setWindowNameUid: function () {
      try
      {
        if (window.name.indexOf('@@@uid=') !== -1)
        {
          return false;
        } else if (window.opener && window.opener.name.indexOf('@@@uid=') !== -1)
        {
          var uid = /@@@uid=(.[^@@@]*)@@@/.exec(window.opener.name)[1];
          window.name = window.name + '@@@uid=' + uid + '@@@';
          return false;
        }
      } catch (ex) { }
      window.name = window.name + '@@@uid=' + hex_md5(new Date().getTime() + window.navigator.userAgent + parseInt(Math.random() * 100000) + window.location.href) + '@@@';
    },
    cookie: function (name, value, options) {
      if (typeof value != 'undefined')
      {
        options = options || {};
        if (value === null)
        {
          value = '';
          options.expires = -1;
        }
        var expires = '';
        if (options.expires && (typeof options.expires == 'number' || options.expires.toUTCString))
        {
          var date;
          if (typeof options.expires == 'number')
          {
            date = new Date();
            date.setTime(date.getTime() + (options.expires * 24 * 60 * 60 * 1000));
          } else
          {
            date = options.expires;
          }
          expires = '; expires=' + date.toUTCString();
        }
        var path = options.path ? '; path=' + options.path : '';
        var domain = options.domain ? '; domain=' + options.domain : '';
        var secure = options.secure ? '; secure' : '';
        document.cookie = [name, '=', value, expires, path, domain, secure].join('');
      } else
      {
        var cookieValue = null;
        if (document.cookie && document.cookie != '')
        {
          var cookies = document.cookie.split(';');
          for (var i = 0; i < cookies.length; i++)
          {
            var cookie = (cookies[i] || "").replace(/(^\s*)|(\s*$)/g, "");
            if (cookie.substring(0, name.length + 1) == (name + '='))
            {
              cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
              break;
            }
          }
        }
        return cookieValue;
      }
    },
    /**
     * 从window.name中取uid
     */
    getWindowNameUid: function () {
      this.setWindowNameUid();
      var uidArr = /@@@uid=(.[^@@@]*)@@@/.exec(window.name);
      return uidArr[1];
    },
    /**
     * [startTryPutData 请求发送失败重试发送]
     * @param  {[type]} src [description]
     * @return {[type]}     [description]
     */
    startTryPutData: function (src) {
      var timer = null;
      var MAXCOUNT = 2;
      var cnt = 0;
      function tryPutData() {
        var img = new Image();
        img.src = src;
        img.onerror = function (e) {
          cnt++;
          if (cnt < MAXCOUNT)
          {
            tryPutData(src);
          }
        }
      }
      tryPutData();
    },
    /**
     * [getEmptyReffer 根据浏览器代理解析来源]
     * @return {[type]} [description]
     */
    getEmptyReffer: function () {
      var ua = navigator.userAgent.toLowerCase();
      var referrer = "";
      if (ua.match(/MicroMessenger/i) == "micromessenger")
      {
        referrer = "weixin";
      }
      if (ua.match(/aliapp/i) == "aliapp" || ua.match(/alipayclient/i) == "alipayclient")
      {
        referrer = "aliapp";
      }
      if (/qq\/\d{1}\./.test(ua))
      { //mobile qq
        referrer = "mqq";
      }
      if (/__weibo__/.test(ua))
      { //weibo
        referrer = "weibo";
      }
      return referrer;
    },
    /**
     *  发送日志
     *  @method putData
     *  @param type {String} => 日志类型,也是发送的图片名称,pe:页面错误,rc:收集页面访问量
     *  @param param {String} => 通过图片发送的参数
     *  @param callback {Function} => 发送信息后回调,发送成功或失败都会走回调
     */
    putData: function (type, param, callback) {
      var me = this;
      var date = new Date().getTime() + "_" + parseInt(Math.random() * 10000);
      var img = new Image();
      param = param ? '&' + param : '';
      var _id = DMS.id || '';
      //var uid = this.getLocalStorage() || this.getWindowNameUid() || '';
      var uid = this.getUid();
      var sign = this.noSign ? 0 : 1;
      var _code = '';
      var referrer = document.referrer;
      try
      {
        referrer = decodeURIComponent(referrer);
      } catch (ex)
      {
        _code = '&code=gbk';
      }
      if (!referrer)
      {
        referrer = this.getEmptyReffer();
      }
      var userId = DMS.userId ? '&mu=' + DMS.userId : '';
      var v = DMS.tagVersion ? '&v=' + DMS.tagVersion : '';
      var winScreenWidth = window.screen.width;
      var winsScreenHeight = window.screen.height;
      var peUrl = "//dms" + this.env + ".ucarinc.com/" + type + ".gif?c=" + _id + "&u=" + uid + param + "&r=" + referrer + "&sign=" + sign + _code + userId + v + '&s=' + winScreenWidth + '*' + winsScreenHeight + "&_=" + date;
      img.src = peUrl;
      img.onload = function () {
        img.onload = null;
        callback && callback();
      };
      img.onerror = function () {
        img.onerror = null;
        //图片发送失败，开始重试
        me.startTryPutData(peUrl);
        callback && callback();
      }
    },
    /**
     * 收集所有流量
     */
    putRc: function () {
      var p = this.delStore();
      p = p ? 'noh=' + p : '';
      this.putData('rc', p);
    },
    /**
     * 去Url里的门店,如果有门店,return 去店后的url
     */
    delStore: function () {
      var _path = window.location.pathname;
      var pathArr = /\/(.[^\/]*)\//.exec(_path);
      if (!pathArr)
      {
        return false;
      }
      var store = pathArr[1];
      var storeArr = this.store;
      var hrefArr = window.location.href.split(_path);
      var hasStoreFlg = false;
      for (var i = 0, len = storeArr.length; i < len; i++)
      {
        if (storeArr[i] === store)
        {
          hasStoreFlg = true;
          _path = _path.replace(new RegExp(store + '/?'), '');
          hrefArr.splice(1, 0, _path);
          return encodeURIComponent(hrefArr.join(''));
        }
      }
      if (!hasStoreFlg)
      {
        return false;
      }
    },
    /**
     * 收集页面报错信息
     * @method getPageErrInfo
     */
    getPageErrInfo: function () {
      var _this = this;
      //取初始化页面时就报的错
      if (DMS.initPe)
      {
        var _init_pe = DMS.initPe.split(',');
        for (var j = 0; j < _init_pe.length; j++)
        {
          _this.putData('pe', _init_pe[j] + '&o=' + encodeURIComponent(window.location.href));
        }
        delete DMS.initPe;
      }
      /**
       * 监听收集页面报错
       * @param message 报错内容
       * @param uri 报错的文件地址
       * @param line 报错的行
       * @param column  报错的列
       */
      window.onerror = function (message, uri, line, column) {
        var p = 'm=' + message + '&uri=' + uri + '&l=' + line + '&c=' + column + '&o=' + encodeURIComponent(window.location.href);
        _this.putData('pe', p);
      }
    },
    /**
     * 自定义事件收集
     * @param options {Object} => 自定义事件对象
     * @param options.type {Number} => 事件类型,默认为0,需要溯源为1
     * @param options.name {String} => 营销事件名称
     * @param options.beName {String} => 自定义事件名称
     * @param options.target {Number} => 统计分享去向 1=>微信朋友圈 2=>微信好友 3=>qq 4=>腾讯微博 5=>qq空间
     * @param options.from {String|Number} => 统计分享渠道来源 1=>微信 2=>买买车appIos 3=>买买车appAndroid
     * @param callback {Function} => 发完信息后回调函数
     */
    putBe: function (options, callback) {
      var p = 'n=' + (options.name ? encodeURIComponent(options.name) : '') + '&t=' + (options.type || 0) + '&be_opt=' + JSON.stringify(options);
      this.putData('be', p, callback);
    },
    /**
     * 利用页面上的[lcwa-se]属性收集自定义事件的点击率
     */
    putClickSe: function () {
      var _evts = document.getElementsByTagName('*');
      var seData = [];
      for (var i = 0, len = _evts.length; i < len; i++)
      {
        var _cls = _evts[i].getAttribute('lcwa-se');
        if (!_cls)
        {
          continue;
        }
        var _val = _cls.split(',');
        Array.prototype.push.apply(seData, _val);
      }
      if (seData.length == 0)
      {
        return false;
      }
      var p = 'se=' + encodeURIComponent(seData.join(',')) + '&t=3';
      this.putData('se', p);
    },
    /**
     * 发送页面打开的时长
     */
    putRt: function () {
      var _this = this;
      if (window.addEventListener)
      {
        if ("onpagehide" in window)
        {
          window.addEventListener('pagehide', function (e) {
            _this.putData('rt', 'time=' + (new Date().getTime() - _this.st));
          })
        } else
        {
          window.addEventListener('beforeunload', function (e) {
            _this.putData('rt', 'time=' + (new Date().getTime() - _this.st));
          })
        }
      } else if (window.attachEvent)
      {
        window.attachEvent('onbeforeunload', function (e) {
          _this.putData('rt', 'time=' + (new Date().getTime() - _this.st));
        })
      }
    },
    getDomPath: function (t) {
      var e,
        n,
        i;
      for (e = []; t && 1 == t.nodeType; t = t.parentNode)
      {
        /*if (t.id) {
            e.unshift(t.tagName.toLowerCase() + '[@id="' + t.id + '"]');
            break;
        } else {*/
        for (n = 0, i = t.previousSibling; i; i = i.previousSibling)
        {
          i.tagName == t.tagName && n++;
        }
        var _id = t.id ? '[@id:' + t.id + ']' : '';
        e.unshift(t.tagName.toLowerCase() + "[" + n + "]" + _id);
        //}
      }
      return e.length ? "/" + e.join("/") : null
    },
    /**
     * 发送页面的点击处
     */
    putCl: function () {
      var _this = this;
      var flg = /(phone|pad|pod|iPhone|iPod|ios|iPad|Android|Mobile|BlackBerry|IEMobile|MQQBrowser|JUC|Fennec|wOSBrowser|BrowserNG|WebOS|Symbian|Windows Phone)/i.test(window.navigator.userAgent);
      var number = '';
      var downFlg = false,
        moveFlg = false;

      function getDown(e) {
        e = e || window.event;
        if (flg)
        {
          if (e.touches.length > 1)
          {
            return false;
          }
          e = e.touches[0];
          downFlg = true;
        }
        var body = document.body;
        var scrollLeft = document.documentElement.scrollLeft || body.scrollLeft;
        var scrollTop = document.documentElement.scrollTop || body.scrollTop;
        var x = e.pageX || e.clientX + scrollLeft;
        var y = e.pageY || e.clientY + scrollTop;
        var cx = e.clientX;
        var cy = e.clientY;
        var bodyWidth = Math.max(document.documentElement.scrollWidth, body.scrollWidth);
        var bodyHeight = Math.max(document.documentElement.scrollHeight, body.scrollHeight);
        number = hex_md5(new Date().getTime() + window.navigator.userAgent + parseInt(Math.random() * 100000) + window.location.href + x + y); //此次统计的唯一标识,用于取消该统计数据
        var t = e.target || e.srcElement;
        var xpath = encodeURIComponent(_this.getDomPath(t));
        var p = _this.delStore();
        p = p ? '&noh=' + p : '';
        var paramStr = 'x=' + parseInt(x) + '&y=' + parseInt(y) + '&cx=' + parseInt(cx) + '&cy=' + parseInt(cy) + '&bw=' + bodyWidth + '&bh=' + bodyHeight + '&sl=' + scrollLeft + '&st=' + scrollTop + '&xpath=' + xpath + '&clnum=' + number + p;
        _this.putData('cl', paramStr);
      }

      function getMove(e) {
        if (downFlg)
        {
          downFlg = false;
          moveFlg = true;
        }
      }
      function domReadyIE(callback) {
        var doScrollMoniterId = null;
        var doScrollMoniter = function () {
          try
          {
            document.documentElement.doScroll("left");
            document.getElementById("divMsg").innerHTML += "<br/>doScroll, readyState:" + document.readyState;
            if (doScrollMoniterId)
            {
              clearInterval(doScrollMoniterId);
              callback && callback();
            }
          }
          catch (ex)
          {

          }
        }
        doScrollMoniterId = setInterval(doScrollMoniter, 1);
      }
      function getEnd(e) {
        if (moveFlg)
        {
          moveFlg = false;
          var param = 'cancelnum=' + number;
          _this.putData('cl', param);
        }
      }
      if (window.addEventListener)
      {
        var _event = flg ? 'touchstart' : 'click';
        window.addEventListener(_event, function (e) {
          getDown(e, flg);
        });
      } else if (window.attachEvent)
      {
        var _event = flg ? 'ontouchstart' : 'onclick';
        domReadyIE(function () {
          document.body.attachEvent(_event, function (e) {
            getDown(e, flg);
          });
        });
      }
      /*var n = !!document.attachEvent;
      var o = n ? 'attachEvent' : 'addEventListener';
      var _event = flg ? 'touchstart' : 'mousedown';
      document[o]((n ? 'on' : '') + _event, function(e) {
        getDown(e);
      });
      flg && window.addEventListener('touchmove', function(e) {
        getMove(e);
      });
      flg && window.addEventListener('touchend', function(e) {
        getEnd(e);
      });*/
    }

  };
  var lc = new LcUtil();

  //暴露方法
  window.DMS.putBe = function () {
    lc.putBe.apply(lc, arguments);
  };
  window.DMS.putData = function () {
    lc.putData.apply(lc, arguments);
  };
})();
