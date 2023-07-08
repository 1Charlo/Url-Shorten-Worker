//Control the HTTP referrer header, if you want to create an anonymous link that will hide the HTTP Referer header, please set to "on" .
const no_ref = typeof(NO_REF)!="undefined" ? NO_REF : "off"

//Allow Cross-origin resource sharing for API requests.
const cors = typeof(CORS)!="undefined" ? CORS : "on"

//If it is true, the same long url will be shorten into the same short url
const unique_link = typeof(UNIQUE_LINK)!="undefined" ? UNIQUE_LINK === 'true' : true

const custom_link = typeof(CUSTOM_LINK)!="undefined" ? CUSTOM_LINK === 'true' : false

const short_len = typeof(SHORT_LEN)!="undefined" ? parseInt(SHORT_LEN) : 6

const safe_browsing_api_key = typeof(SAFE_BROWSING_API_KEY)!="undefined" ? SAFE_BROWSING_API_KEY : ""

// 白名单中的域名无视超时，json数组格式，写顶级域名就可以，自动通过顶级域名和所有二级域名，
const white_list = JSON.parse(typeof(WHITE_LIST)!="undefined" ? WHITE_LIST : `[]`)

// 短链超时，单位秒
const shorten_timeout = typeof(SHORTEN_TIMEOUT)!="undefined" ? parseInt(SHORTEN_TIMEOUT) : 86400
if (shorten_timeout > 31536000) {
  shorten_timeout = 31536000
}

// 白名单中短链超时，单位秒
const white_timeoout = typeof(WHITE_TIMEOOUT)!="undefined" ? parseInt(WHITE_TIMEOOUT) : 31536000
if (white_timeoout > 31536000) {
  white_timeoout = 31536000
}

const ip_req_day_limit = typeof(IP_REQ_DAY_LIMIT)!="undefined" ? parseInt(IP_REQ_DAY_LIMIT) : 100

const html404 = `<!DOCTYPE html>
<body>
  <h1>404 Not Found.</h1>
  <p>The url you visit is not found.</p>
</body>`

let response_header={
  "content-type": "text/html;charset=UTF-8",
} 

if (cors=="on"){
  response_header={
  "content-type": "text/html;charset=UTF-8",
  "Access-Control-Allow-Origin":"*",
  "Access-Control-Allow-Methods": "POST",
  }
}

async function randomString() {
　　len = short_len;
　　let $chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';    /****默认去掉了容易混淆的字符oOLl,9gq,Vv,Uu,I1****/
　　let maxPos = $chars.length;
　　let result = '';
　　for (i = 0; i < len; i++) {
　　　　result += $chars.charAt(Math.floor(Math.random() * maxPos));
　　}
　　return result;
}

async function sha512(url){
    url = new TextEncoder().encode(url)

    const url_digest = await crypto.subtle.digest(
      {
        name: "SHA-512",
      },
      url, // The data you want to hash as an ArrayBuffer
    )
    const hashArray = Array.from(new Uint8Array(url_digest)); // convert buffer to byte array
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    //console.log(hashHex)
    return hashHex
}
async function checkURL(URL){
    let str=URL;
    let Expression=/http(s)?:\/\/([\w-]+\.)+[\w-]+(\/[\w- .\/?%&=]*)?/;
    let objExp=new RegExp(Expression);
    if(objExp.test(str)==true){
      if (str[0] == 'h')
        return true;
      else
        return false;
    }else{
        return false;
    }
}

// 获取key需要被设置的过期时间(s)
async function keyExpiredTtl(url){
  let host = new URL(url).host
  let inWhite = white_list.some((h) => host == h || host.endsWith('.'+h))
  if(inWhite){
    return white_timeoout
  }else{
    return shorten_timeout
  }
}

async function save_url(URL){
    let random_key=await randomString()
    let is_exist=await LINKS.get(random_key)
    console.log(is_exist)
    if (is_exist == null){
      let ttl = await keyExpiredTtl(URL)
      return await LINKS.put(random_key, URL,{expirationTtl: ttl}),random_key
    }else{
      save_url(URL)
    }
}
async function is_url_exist(url_sha512){
  let is_exist = await LINKS.get(url_sha512)
  console.log(is_exist)
  if (is_exist == null) {
    return false
  }else{
    return is_exist
  }
}
async function is_url_safe(url){

  let raw = JSON.stringify({"client":{"clientId":"Url-Shorten-Worker","clientVersion":"1.0.7"},"threatInfo":{"threatTypes":["MALWARE","SOCIAL_ENGINEERING","POTENTIALLY_HARMFUL_APPLICATION","UNWANTED_SOFTWARE"],"platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],"threatEntries":[{"url":url}]}});

  let requestOptions = {
    method: 'POST',
    body: raw,
    redirect: 'follow'
  };

  result = await fetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key="+safe_browsing_api_key, requestOptions)
  result = await result.json()
  console.log(result)
  if (Object.keys(result).length === 0){
    return true
  }else{
    return false
  }
}

async function ipFrequencyLimit(request) {
  let clientIP = request.headers.get("CF-Connecting-IP")
  ipKey = clientIP.replaceAll(".", "-").replaceAll(":", "-")
  ipReqData = await LINKS.get(ipKey)
  const timeStamp = await Date.parse(new Date()) / 1000;
  if (ipReqData == null) {
    let expir = timeStamp + 86400
    let value = expir.toString() + ',' + 1
    LINKS.put(ipKey, value, {expiration: expir})
    return false
  }else {
    let expir = parseInt(ipReqData.split(',')[0])
    let num = parseInt(ipReqData.split(',')[1])
    if (num > ip_req_day_limit) {
      return true
    }
    LINKS.put(ipKey, num+1, {expiration: expir})
    return false
  }
}

async function handleRequest(request) {
  console.log(request)
  let ipLimit = await ipFrequencyLimit(request)
  if (ipLimit) {
    return new Response(`{"status":500,"key":": Error: ip is restricted."}`, {
      headers: response_header,
    })}
  }
  const requestURL = new URL(request.url)
  const path = requestURL.pathname.split("/")[1]
  const params = requestURL.search
  const origin = requestURL.origin
  let hasUrl = false
  if (params) {
    urlParams = new URLSearchParams(params.split("?")[1])
    hasUrl = urlParams.has("url")
  }

  if (request.method === "POST" || (request.method === "GET" && !path && params && hasUrl)) {
    let url = '';
    if (request.method === "POST"){
      let req=await request.json()
      url = req["url"]
    }else{
      urlParams = new URLSearchParams(params.split("?")[1])
      url = urlParams.get("url")
    }
    
    console.log(url)
    if(!await checkURL(url)){
    return new Response(`{"status":500,"key":": Error: Url illegal."}`, {
      headers: response_header,
    })}
    let stat,random_key
    if (unique_link){
      let url_sha512 = await sha512(url)
      let url_key = await is_url_exist(url_sha512)
      if(url_key){
        random_key = url_key
      }else{
        stat,random_key=await save_url(url)
        if (typeof(stat) == "undefined"){
          let ttl = await keyExpiredTtl(url)
          console.log(await LINKS.put(url_sha512,random_key,{expirationTtl: ttl}))
        }
      }
    }else{
      stat,random_key=await save_url(url)
    }
    console.log(stat)
    if (typeof(stat) == "undefined"){
      short_key = origin + "/" + random_key
      return new Response(`{"status":200,"key":"` + short_key + `"}`, {
      headers: response_header,
    })
    }else{
      return new Response(`{"status":200,"key":": Error:Reach the KV write limitation."}`, {
      headers: response_header,
    })}
  }else if(request.method === "OPTIONS"){
      return new Response(``, {
      headers: response_header,
    })

  }

  console.log(path)
  if(!path){

    const html= await fetch("https://fastly.jsdelivr.net/gh/1Charlo/Url-Shorten-Worker/index.html")
    
    return new Response(await html.text(), {
    headers: {
      "content-type": "text/html;charset=UTF-8",
    },
  })
  }

  const value = await LINKS.get(path)
  let location ;

  if(params) {
    location = value + params
  } else {
      location = value
  }
  console.log(value)
  

  if (location) {
    if (safe_browsing_api_key){
      if(!(await is_url_safe(location))){
        let warning_page = await fetch("https://fastly.jsdelivr.net/gh/1Charlo/Url-Shorten-Worker/safe-browsing.html")
        warning_page =await warning_page.text()
        warning_page = warning_page.replace(/{Replace}/gm, location)
        return new Response(warning_page, {
          headers: {
            "content-type": "text/html;charset=UTF-8",
          },
        })
      }
    }
    if (no_ref=="on"){
      let no_ref= await fetch("https://fastly.jsdelivr.net/gh/1Charlo/Url-Shorten-Worker/no-ref.html")
      no_ref=await no_ref.text()
      no_ref=no_ref.replace(/{Replace}/gm, location)
      return new Response(no_ref, {
      headers: {
        "content-type": "text/html;charset=UTF-8",
      },
    })
    }else{
      return Response.redirect(location, 302)
    }
    
  }
  // If request not in kv, return 404
  return new Response(html404, {
    headers: {
      "content-type": "text/html;charset=UTF-8",
    },
    status: 404
  })
}



addEventListener("fetch", async event => {
  event.respondWith(handleRequest(event.request))
})
