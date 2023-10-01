import index_page from './pages/index.html';
import noref_page from './pages/no-ref.html';
import safebrowsing_page from './pages/safe-browsing.html';


var LINKS = null;

//Control the HTTP referrer header, if you want to create an anonymous link that will hide the HTTP Referer header, please set to "on" .
var no_ref = null;
//Allow Cross-origin resource sharing for API requests.
var cors = null;
//If it is true, the same long url will be shorten into the same short url
var unique_link = null;
var custom_link = null;
var short_len = null;
var safe_browsing_api_key = null;
// 白名单中的域名无视超时，json数组格式，写顶级域名就可以，自动通过顶级域名和所有二级域名，
var white_list = null;
// 短链超时，单位秒
var shorten_timeout = null;
// 白名单中短链超时，单位秒
var white_timeoout = null;
var ip_req_day_limit = null;

const html404 = `<!DOCTYPE html>
<body>
  <h1>404 Not Found.</h1>
  <p>The url you visit is not found.</p>
</body>`;

let response_header = {
    "content-type": "text/html;charset=UTF-8",
}

async function randomString() {
    let len = short_len;
    let $chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';    /****默认去掉了容易混淆的字符oOLl,9gq,Vv,Uu,I1****/
    let maxPos = $chars.length;
    let result = '';
    for (let i = 0; i < len; i++) {
        result += $chars.charAt(Math.floor(Math.random() * maxPos));
    }
    return result;
}

async function sha512(url) {
    url = new TextEncoder().encode(url);

    const url_digest = await crypto.subtle.digest(
        {
            name: "SHA-512",
        },
        url, // The data you want to hash as an ArrayBuffer
    );
    const hashArray = Array.from(new Uint8Array(url_digest)); // convert buffer to byte array
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    //console.log(hashHex)
    return hashHex;
}
async function checkURL(URL) {
    let str = URL;
    let Expression = /http(s)?:\/\/([\w-]+\.)+[\w-]+(\/[\w- .\/?%&=]*)?/;
    let objExp = new RegExp(Expression);
    if (objExp.test(str) == true) {
        if (str[0] == 'h')
            return true;
        else
            return false;
    } else {
        return false;
    }
}

// 获取key需要被设置的过期时间(s)
async function keyExpiredTtl(url) {
    let host = new URL(url).host;
    let inWhite = white_list.some((h) => host == h || host.endsWith('.' + h));
    if (inWhite) {
        return white_timeoout;
    } else {
        return shorten_timeout;
    }
}

async function save_url(URL) {
    let random_key = await randomString();
    let is_exist = await LINKS.get(random_key);
    if (is_exist == null) {
        let ttl = await keyExpiredTtl(URL);
        return await LINKS.put(random_key, URL, { expirationTtl: ttl }), random_key;
    } else {
        save_url(URL);
    }
}
async function is_url_exist(url_sha512) {
    let is_exist = await LINKS.get(url_sha512);
    console.log(is_exist);
    if (is_exist == null) {
        return false;
    } else {
        return is_exist;
    }
}
async function is_url_safe(url) {

    let raw = JSON.stringify({ "client": { "clientId": "Url-Shorten-Worker", "clientVersion": "1.0.7" }, "threatInfo": { "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION", "UNWANTED_SOFTWARE"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{ "url": url }] } });

    let requestOptions = {
        method: 'POST',
        body: raw,
        redirect: 'follow'
    };

    result = await fetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + safe_browsing_api_key, requestOptions);
    result = await result.json();
    console.log(result);
    if (Object.keys(result).length === 0) {
        return true;
    } else {
        return false;
    }
}

async function ipFrequencyLimit(request) {
    let clientIP = request.headers.get("CF-Connecting-IP");
    let ipKey = clientIP.replaceAll(".", "-").replaceAll(":", "-");
    let ipReqData = await LINKS.get(ipKey);
    let timeStamp = await Date.parse(new Date()) / 1000;
    if (ipReqData == null) {
        let expir = timeStamp + 86400;
        let value = expir.toString() + ',' + 1;
        LINKS.put(ipKey, value, { expiration: expir });
        return false;
    } else {
        let expir = parseInt(ipReqData.split(',')[0]);
        let num = parseInt(ipReqData.split(',')[1]);
        if (num >= ip_req_day_limit) {
            return true;
        }
        let value = expir.toString() + ',' + (num + 1);
        LINKS.put(ipKey, value, { expiration: expir });
        return false;
    }
}

async function handleRequest(request) {
    console.info("start time: " + new Date().getTime());
    const requestURL = new URL(request.url);
    const path = requestURL.pathname.split("/")[1];
    const params = requestURL.search;
    const origin = requestURL.origin;
    let hasUrl = false;
    if (params) {
        let urlParams = new URLSearchParams(params.split("?")[1]);
        hasUrl = await urlParams.has("url");
    }

    if (request.method === "POST" || (request.method === "GET" && !path && params && hasUrl)) {

        // 对ip的每日短链转换次数做限制
        let ipLimit = await ipFrequencyLimit(request);
        if (ipLimit) {
            return new Response(`{"status":500,"key":"Error: ip is restricted."}`, {
                headers: response_header,
            });
        }

        let url = '';
        if (request.method === "POST") {
            let req = await request.json();
            url = req["url"];
        } else {
            let urlParams = new URLSearchParams(params.split("?")[1]);
            url = await urlParams.get("url");
        }

        console.log(url);
        if (!await checkURL(url)) {
            return new Response(`{"status":500,"key":"Error: Url illegal."}`, {
                headers: response_header,
            });
        }
        let stat, random_key;
        if (unique_link) {
            let url_sha512 = await sha512(url);
            let url_key = await is_url_exist(url_sha512);
            if (url_key) {
                random_key = url_key;
            } else {
                stat, random_key = await save_url(url);
                if (typeof (stat) == "undefined") {
                    let ttl = await keyExpiredTtl(url);
                    await LINKS.put(url_sha512, random_key, { expirationTtl: ttl });
                }
            }
        } else {
            stat, random_key = await save_url(url);
        }
        if (typeof (stat) == "undefined") {
            console.info("end time: " + new Date().getTime());
            let short_key = origin + "/" + random_key;
            return new Response(`{"status":200,"key":"` + short_key + `"}`, {
                headers: response_header,
            });
        } else {
            console.info("end time: " + new Date().getTime());
            return new Response(`{"status":200,"key":"Error: Reach the KV write limitation."}`, {
                headers: response_header,
            });
        }
    } else if (request.method === "OPTIONS") {
        console.info("end time: " + new Date().getTime());
        return new Response(``, {
            headers: response_header,
        });
    }

    if (!path) {
        let html = index_page;
        console.info("end time: " + new Date().getTime());
        return new Response(html, {
            headers: {
                "content-type": "text/html;charset=UTF-8",
            },
        });
    }

    const value = await LINKS.get(path);
    let location;

    if (params) {
        location = value + params;
    } else {
        location = value;
    }

    if (location) {
        if (safe_browsing_api_key) {
            if (!(await is_url_safe(location))) {
                let warning_page = safebrowsing_page;
                warning_page = warning_page.replace(/{Replace}/gm, location);
                console.info("end time: " + new Date().getTime());
                return new Response(warning_page, {
                    headers: {
                        "content-type": "text/html;charset=UTF-8",
                    },
                });
            }
        }
        if (no_ref == "on") {
            let no_ref_data = noref_page;
            no_ref_data = no_ref_data.replace(/{Replace}/gm, location);
            console.info("end time: " + new Date().getTime());
            return new Response(no_ref_data, {
                headers: {
                    "content-type": "text/html;charset=UTF-8",
                },
            });
        } else {
            console.info("end time: " + new Date().getTime());
            return Response.redirect(location, 302);
        }

    }
    console.info("end time: " + new Date().getTime());
    // If request not in kv, return 404
    return new Response(html404, {
        headers: {
            "content-type": "text/html;charset=UTF-8",
        },
        status: 404
    });
}


function getEnvs(env) {
    LINKS = env.LINKS;

    //Control the HTTP referrer header, if you want to create an anonymous link that will hide the HTTP Referer header, please set to "on" .
    no_ref = typeof (env.NO_REF) != "undefined" ? env.NO_REF : "off";

    //Allow Cross-origin resource sharing for API requests.
    cors = typeof (env.CORS) != "undefined" ? env.CORS : "on";
    if (cors == "on") {
        response_header = {
            "content-type": "text/html;charset=UTF-8",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST",
        }
    }
    //If it is true, the same long url will be shorten into the same short url
    unique_link = typeof (env.UNIQUE_LINK) != "undefined" ? env.UNIQUE_LINK === 'true' : true;

    custom_link = typeof (env.CUSTOM_LINK) != "undefined" ? env.CUSTOM_LINK === 'true' : false;

    short_len = typeof (env.SHORT_LEN) != "undefined" ? parseInt(env.SHORT_LEN) : 6;

    safe_browsing_api_key = typeof (env.SAFE_BROWSING_API_KEY) != "undefined" ? env.SAFE_BROWSING_API_KEY : "";

    // 白名单中的域名无视超时，json数组格式，写顶级域名就可以，自动通过顶级域名和所有二级域名，
    white_list = JSON.parse(typeof (env.WHITE_LIST) != "undefined" ? env.WHITE_LIST : `[]`);

    // 短链超时，单位秒
    shorten_timeout = typeof (env.SHORTEN_TIMEOUT) != "undefined" ? parseInt(env.SHORTEN_TIMEOUT) : 86400;

    if (shorten_timeout > 31536000) {
        shorten_timeout = 31536000
    }

    // 白名单中短链超时，单位秒
    white_timeoout = typeof (env.WHITE_TIMEOOUT) != "undefined" ? parseInt(env.WHITE_TIMEOOUT) : 31536000;
    if (white_timeoout > 31536000) {
        white_timeoout = 31536000
    }

    ip_req_day_limit = typeof (env.IP_REQ_DAY_LIMIT) != "undefined" ? parseInt(env.IP_REQ_DAY_LIMIT) : 100;
}

export default {
    async fetch(request, env, ctx) {
        getEnvs(env);
        return await handleRequest(request);
    },
};
